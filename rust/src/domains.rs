use crate::flow::FlowIndex;
use crate::pcap::{L4Proto, PacketRow};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Default)]
pub struct DomainStats {
    pub queries: u64,
    pub responses: u64,
    pub failures: u64,
    pub ips: BTreeSet<IpAddr>,
}

#[derive(Debug, Clone)]
pub struct DomainItem {
    pub domain: String,
    pub stats: DomainStats,
    pub flow_indices: Vec<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct DomainsSummary {
    pub items: Vec<DomainItem>,
}

pub fn build_domains_summary(rows: &[PacketRow], flows: &FlowIndex) -> DomainsSummary {
    let mut map: BTreeMap<String, DomainStats> = BTreeMap::new();

    for r in rows {
        // DNS source (UDP/53 payload parse)
        if r.proto == Some(L4Proto::Udp) {
            // DNS is usually 53/udp.
            let sp = r.src_port.unwrap_or(0);
            let dp = r.dst_port.unwrap_or(0);
            if sp == 53 || dp == 53 {
                if let Some(msg) = parse_dns_message(&r.payload) {
                    if !msg.qname.is_empty() {
                        let e = map.entry(msg.qname).or_default();
                        if msg.is_response {
                            e.responses += 1;
                            if msg.rcode != 0 {
                                e.failures += 1;
                            }
                            for ip in msg.answer_ips {
                                e.ips.insert(ip);
                            }
                        } else {
                            e.queries += 1;
                        }
                    }
                }
            }
        }

        // HTTP Host hint (plaintext)
        if let Some(host) = &r.http_host {
            let e = map.entry(host.clone()).or_default();
            e.queries += 1;
        }

        // TLS SNI hint
        if let Some(sni) = &r.tls_sni {
            let e = map.entry(sni.clone()).or_default();
            e.queries += 1;
        }
    }

    // Build flow subsets per domain.
    let mut items: Vec<DomainItem> = Vec::new();
    for (domain, stats) in map {
        let flow_indices = if stats.ips.is_empty() {
            // If we don't have IPs, restrict to DNS traffic only.
            flows
                .flows
                .iter()
                .enumerate()
                .filter(|(_i, f)| {
                    f.key.proto == L4Proto::Udp && (f.key.src_port == 53 || f.key.dst_port == 53)
                })
                .map(|(i, _)| i)
                .collect()
        } else {
            flows
                .flows
                .iter()
                .enumerate()
                .filter(|(_i, f)| stats.ips.contains(&f.key.src) || stats.ips.contains(&f.key.dst))
                .map(|(i, _)| i)
                .collect()
        };

        items.push(DomainItem {
            domain,
            stats,
            flow_indices,
        });
    }

    // Sort by queries+responses, then failures.
    items.sort_by(|a, b| {
        let ac = a.stats.queries + a.stats.responses;
        let bc = b.stats.queries + b.stats.responses;
        bc.cmp(&ac)
            .then_with(|| b.stats.failures.cmp(&a.stats.failures))
            .then_with(|| a.domain.cmp(&b.domain))
    });

    DomainsSummary { items }
}

#[derive(Debug, Clone)]
struct DnsParsed {
    qname: String,
    is_response: bool,
    rcode: u8,
    answer_ips: Vec<IpAddr>,
}

fn parse_dns_message(buf: &[u8]) -> Option<DnsParsed> {
    if buf.len() < 12 {
        return None;
    }

    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let is_response = (flags & 0x8000) != 0;
    let rcode = (flags & 0x000f) as u8;

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut off = 12usize;

    // First question only.
    let mut qname = String::new();
    if qdcount > 0 {
        let (name, n_off) = read_name(buf, off, 0)?;
        qname = name;
        off = n_off;
        if off + 4 > buf.len() {
            return None;
        }
        // qtype, qclass
        off += 4;
    }

    let mut answer_ips: Vec<IpAddr> = Vec::new();

    // Parse answers for A/AAAA.
    for _ in 0..ancount {
        let (_name, n_off) = read_name(buf, off, 0)?;
        off = n_off;
        if off + 10 > buf.len() {
            return None;
        }
        let rr_type = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let _rr_class = u16::from_be_bytes([buf[off + 2], buf[off + 3]]);
        let _ttl = u32::from_be_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
        let rdlen = u16::from_be_bytes([buf[off + 8], buf[off + 9]]) as usize;
        off += 10;
        if off + rdlen > buf.len() {
            return None;
        }

        match rr_type {
            1 /* A */ if rdlen == 4 => {
                let ip = Ipv4Addr::new(buf[off], buf[off + 1], buf[off + 2], buf[off + 3]);
                answer_ips.push(IpAddr::V4(ip));
            }
            28 /* AAAA */ if rdlen == 16 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&buf[off..off + 16]);
                answer_ips.push(IpAddr::V6(Ipv6Addr::from(b)));
            }
            _ => {}
        }

        off += rdlen;
    }

    Some(DnsParsed {
        qname,
        is_response,
        rcode,
        answer_ips,
    })
}

fn read_name(buf: &[u8], mut off: usize, depth: usize) -> Option<(String, usize)> {
    if depth > 10 {
        return None;
    }

    let mut labels: Vec<String> = Vec::new();
    let start_off = off;
    let mut jumped = false;

    loop {
        if off >= buf.len() {
            return None;
        }
        let len = buf[off];
        if len == 0 {
            off += 1;
            break;
        }

        // compression pointer
        if (len & 0b1100_0000) == 0b1100_0000 {
            if off + 1 >= buf.len() {
                return None;
            }
            let ptr = (((len as u16 & 0x3f) << 8) | buf[off + 1] as u16) as usize;
            let (name, _end) = read_name(buf, ptr, depth + 1)?;
            if !name.is_empty() {
                labels.push(name);
            }
            off += 2;
            jumped = true;
            break;
        }

        let n = len as usize;
        off += 1;
        if off + n > buf.len() {
            return None;
        }
        let label = std::str::from_utf8(&buf[off..off + n]).ok()?.to_string();
        labels.push(label);
        off += n;
    }

    let name = labels.join(".").trim_end_matches('.').to_lowercase();
    let end_off = if jumped { start_off + 2 } else { off };
    Some((name, end_off))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_dns_query_name() {
        // Minimal DNS query for "example.com" type A.
        // Header: id=0x0001 flags=0x0100 qd=1 an=0 ns=0 ar=0
        let mut b: Vec<u8> = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        // qname
        b.extend_from_slice(&[7]);
        b.extend_from_slice(b"example");
        b.extend_from_slice(&[3]);
        b.extend_from_slice(b"com");
        b.push(0);
        // qtype A, qclass IN
        b.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        let p = parse_dns_message(&b).unwrap();
        assert_eq!(p.qname, "example.com");
        assert!(!p.is_response);
    }
}
