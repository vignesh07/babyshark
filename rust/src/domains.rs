use crate::flow::FlowIndex;
use crate::pcap::{L4Proto, PacketRow};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Default)]
pub struct DomainStats {
    pub queries: u64,
    pub responses: u64,
    pub failures: u64,

    /// IPs learned from DNS answers (A/AAAA) when visible.
    pub dns_ips: BTreeSet<IpAddr>,

    /// IPs observed directly from flows that carried this hostname (works even with DoH).
    pub observed_ips: BTreeSet<IpAddr>,

    /// Approx "connections" for this domain: number of flows associated with it.
    pub connections: u64,

    /// Total bytes across associated flows (best-effort).
    pub bytes: u64,
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

/// Build a best-effort IP → hostname index from the capture.
///
/// Sources:
/// - DNS A/AAAA answers (offline payload parsing)
/// - TLS SNI / HTTP Host hints (live or offline)
///
/// If multiple hostnames map to the same IP, we pick the most frequently observed.
pub fn build_ip_hostname_index(
    rows: &[PacketRow],
) -> std::collections::BTreeMap<std::net::IpAddr, String> {
    use std::collections::{BTreeMap, HashMap};
    use std::net::IpAddr;

    let mut counts: HashMap<IpAddr, HashMap<String, u64>> = HashMap::new();

    for r in rows {
        // DNS answers (offline payload)
        if r.proto == Some(crate::pcap::L4Proto::Udp) {
            let sp = r.src_port.unwrap_or(0);
            let dp = r.dst_port.unwrap_or(0);
            if sp == 53 || dp == 53 {
                if let Some(msg) = parse_dns_message(&r.payload) {
                    if msg.is_response && !msg.qname.is_empty() {
                        for ip in msg.answer_ips {
                            *counts
                                .entry(ip)
                                .or_default()
                                .entry(msg.qname.clone())
                                .or_default() += 1;
                        }
                    }
                }
            }
        }

        // TLS SNI / HTTP Host hints (works live)
        if let Some(dst) = r.dst {
            if let Some(sni) = r.tls_sni.as_deref() {
                *counts
                    .entry(dst)
                    .or_default()
                    .entry(sni.to_string())
                    .or_default() += 1;
            }
            if let Some(host) = r.http_host.as_deref() {
                *counts
                    .entry(dst)
                    .or_default()
                    .entry(host.to_string())
                    .or_default() += 1;
            }
        }
    }

    let mut out: BTreeMap<IpAddr, String> = BTreeMap::new();
    for (ip, m) in counts {
        if let Some((best, _n)) = m.into_iter().max_by_key(|(_k, v)| *v) {
            out.insert(ip, best);
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainsSort {
    Connections,
    Bytes,
    Failures,
}

pub fn build_domains_summary(rows: &[PacketRow], flows: &FlowIndex, sort: DomainsSort) -> DomainsSummary {

    let mut map: BTreeMap<String, DomainStats> = BTreeMap::new();
    let mut conns: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();

    // Fast lookup: canonical FlowKey -> index in flows.flows
    let mut flow_lookup: std::collections::HashMap<crate::pcap::FlowKey, usize> =
        std::collections::HashMap::new();
    for (i, fl) in flows.flows.iter().enumerate() {
        flow_lookup.insert(fl.key.clone(), i);
    }

    for r in rows {
        // DNS source (prefer payload parse; fall back to live hints)
        if r.proto == Some(L4Proto::Udp) {
            // DNS is usually 53/udp.
            let sp = r.src_port.unwrap_or(0);
            let dp = r.dst_port.unwrap_or(0);
            if sp == 53 || dp == 53 {
                if let Some(msg) = parse_dns_message(&r.payload) {
                    if !msg.qname.is_empty() {
                        if let Some(fk) = &r.flow {
                            let (canon, _flipped) = fk.canonical();
                            if let Some(flow_i) = flow_lookup.get(&canon) {
                                conns.entry(msg.qname.clone()).or_default().insert(*flow_i);
                            }
                        }

                        let e = map.entry(msg.qname).or_default();
                        if msg.is_response {
                            e.responses += 1;
                            if msg.rcode != 0 {
                                e.failures += 1;
                            }
                            for ip in msg.answer_ips {
                                e.dns_ips.insert(ip);
                            }
                        } else {
                            e.queries += 1;
                        }
                    }
                } else if let Some(qname) = r.dns_qname.as_deref() {
                    // Live mode (no payload): tshark fields can provide qname + rcode.
                    if let Some(fk) = &r.flow {
                        let (canon, _flipped) = fk.canonical();
                        if let Some(flow_i) = flow_lookup.get(&canon) {
                            conns.entry(qname.to_string()).or_default().insert(*flow_i);
                        }
                    }

                    let e = map.entry(qname.to_string()).or_default();
                    // Best-effort: if we saw an rcode, treat it as a response.
                    if let Some(rcode) = r.dns_rcode {
                        e.responses += 1;
                        if rcode != 0 {
                            e.failures += 1;
                        }
                    } else {
                        e.queries += 1;
                    }
                }
            }
        }

        // HTTP Host hint (plaintext)
        if let Some(host) = &r.http_host {
            if let Some(dst) = r.dst {
                map.entry(host.clone()).or_default().observed_ips.insert(dst);
            }
            if let Some(src) = r.src {
                map.entry(host.clone()).or_default().observed_ips.insert(src);
            }
            if let Some(fk) = &r.flow {
                let (canon, _flipped) = fk.canonical();
                if let Some(flow_i) = flow_lookup.get(&canon) {
                    conns.entry(host.clone()).or_default().insert(*flow_i);
                }
            }

            let e = map.entry(host.clone()).or_default();
            e.queries += 1;
        }

        // TLS SNI hint
        if let Some(sni) = &r.tls_sni {
            if let Some(dst) = r.dst {
                map.entry(sni.clone()).or_default().observed_ips.insert(dst);
            }
            if let Some(src) = r.src {
                map.entry(sni.clone()).or_default().observed_ips.insert(src);
            }
            if let Some(fk) = &r.flow {
                let (canon, _flipped) = fk.canonical();
                if let Some(flow_i) = flow_lookup.get(&canon) {
                    conns.entry(sni.clone()).or_default().insert(*flow_i);
                }
            }

            let e = map.entry(sni.clone()).or_default();
            e.queries += 1;
        }
    }

    // Build flow subsets per domain.
    let mut items: Vec<DomainItem> = Vec::new();
    for (domain, stats) in map {
        let flow_indices: Vec<usize> = if !stats.observed_ips.is_empty() {
            flows
                .flows
                .iter()
                .enumerate()
                .filter(|(_i, f)| {
                    stats.observed_ips.contains(&f.key.src) || stats.observed_ips.contains(&f.key.dst)
                })
                .map(|(i, _)| i)
                .collect()
        } else if !stats.dns_ips.is_empty() {
            flows
                .flows
                .iter()
                .enumerate()
                .filter(|(_i, f)| stats.dns_ips.contains(&f.key.src) || stats.dns_ips.contains(&f.key.dst))
                .map(|(i, _)| i)
                .collect()
        } else {
            // If we don't have any IPs yet, restrict to DNS traffic only.
            flows
                .flows
                .iter()
                .enumerate()
                .filter(|(_i, f)| {
                    f.key.proto == L4Proto::Udp && (f.key.src_port == 53 || f.key.dst_port == 53)
                })
                .map(|(i, _)| i)
                .collect()
        };

        let mut stats = stats;
        let conn_set = conns.get(&domain);
        stats.connections = conn_set.map(|s| s.len() as u64).unwrap_or(0);
        stats.bytes = conn_set
            .map(|s| s.iter().filter_map(|i| flows.flows.get(*i)).map(|f| f.total_bytes).sum())
            .unwrap_or(0);

        items.push(DomainItem {
            domain,
            stats,
            flow_indices,
        });
    }

    match sort {
        DomainsSort::Connections => {
            // Sort by connections (flows), then failures, then activity.
            items.sort_by(|a, b| {
                b.stats
                    .connections
                    .cmp(&a.stats.connections)
                    .then_with(|| b.stats.failures.cmp(&a.stats.failures))
                    .then_with(|| {
                        let ac = a.stats.queries + a.stats.responses;
                        let bc = b.stats.queries + b.stats.responses;
                        bc.cmp(&ac)
                    })
                    .then_with(|| a.domain.cmp(&b.domain))
            });
        }
        DomainsSort::Bytes => {
            // Sort by bytes (desc), then connections, then failures.
            items.sort_by(|a, b| {
                b.stats
                    .bytes
                    .cmp(&a.stats.bytes)
                    .then_with(|| b.stats.connections.cmp(&a.stats.connections))
                    .then_with(|| b.stats.failures.cmp(&a.stats.failures))
                    .then_with(|| a.domain.cmp(&b.domain))
            });
        }
        DomainsSort::Failures => {
            // Sort by failures (desc), then connections, then activity.
            items.sort_by(|a, b| {
                b.stats
                    .failures
                    .cmp(&a.stats.failures)
                    .then_with(|| b.stats.connections.cmp(&a.stats.connections))
                    .then_with(|| {
                        let ac = a.stats.queries + a.stats.responses;
                        let bc = b.stats.queries + b.stats.responses;
                        bc.cmp(&ac)
                    })
                    .then_with(|| a.domain.cmp(&b.domain))
            });
        }
    }

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

    #[test]
    fn domains_sort_by_connections() {
        use chrono::{TimeZone, Utc};

        let mk = |idx: usize, host: &str, sp: u16, dp: u16| PacketRow {
            index: idx,
            ts: Utc.timestamp_opt(0, 0).unwrap(),
            len: 60,
            src: Some("10.0.0.2".parse().unwrap()),
            dst: Some("93.184.216.34".parse().unwrap()),
            proto: Some(L4Proto::Tcp),
            src_port: Some(sp),
            dst_port: Some(dp),
            summary: String::new(),
            flow: Some(crate::pcap::FlowKey {
                src: "10.0.0.2".parse().unwrap(),
                dst: "93.184.216.34".parse().unwrap(),
                src_port: sp,
                dst_port: dp,
                proto: L4Proto::Tcp,
            }),
            flow_dir: Some(crate::pcap::FlowDir::AtoB),
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            payload: Vec::new(),
            tcp_retransmission: false,
            tcp_out_of_order: false,
            dns_qname: None,
            dns_rcode: None,
            http_host: Some(host.to_string()),
            tls_sni: None,
            tls_version: None,
        };

        // a.com appears on 2 distinct flows (different src ports); b.com only on 1.
        let rows = vec![
            mk(0, "a.com", 1111, 80),
            mk(1, "a.com", 2222, 80),
            mk(2, "b.com", 3333, 80),
        ];
        let flows = crate::flow::FlowIndex::build(&rows);
        let dom = build_domains_summary(&rows, &flows, DomainsSort::Connections);

        assert_eq!(dom.items.first().unwrap().domain, "a.com");
        assert_eq!(dom.items.first().unwrap().stats.connections, 2);
    }

    #[test]
    fn domains_sort_by_bytes() {
        use chrono::{TimeZone, Utc};

        let mk = |idx: usize, host: &str, len: usize, sp: u16, dp: u16| PacketRow {
            index: idx,
            ts: Utc.timestamp_opt(0, 0).unwrap(),
            len,
            src: Some("10.0.0.2".parse().unwrap()),
            dst: Some("93.184.216.34".parse().unwrap()),
            proto: Some(L4Proto::Tcp),
            src_port: Some(sp),
            dst_port: Some(dp),
            summary: String::new(),
            flow: Some(crate::pcap::FlowKey {
                src: "10.0.0.2".parse().unwrap(),
                dst: "93.184.216.34".parse().unwrap(),
                src_port: sp,
                dst_port: dp,
                proto: L4Proto::Tcp,
            }),
            flow_dir: Some(crate::pcap::FlowDir::AtoB),
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            payload: Vec::new(),
            tcp_retransmission: false,
            tcp_out_of_order: false,
            dns_qname: None,
            dns_rcode: None,
            http_host: Some(host.to_string()),
            tls_sni: None,
            tls_version: None,
        };

        // a.com: 1 flow but lots of bytes; b.com: 2 flows but tiny.
        let rows = vec![
            mk(0, "a.com", 1500, 1111, 80),
            mk(1, "b.com", 60, 2222, 80),
            mk(2, "b.com", 60, 3333, 80),
        ];
        let flows = crate::flow::FlowIndex::build(&rows);
        let dom = build_domains_summary(&rows, &flows, DomainsSort::Bytes);

        assert_eq!(dom.items.first().unwrap().domain, "a.com");
        assert!(dom.items.first().unwrap().stats.bytes >= 1500);
    }

    #[test]
    fn domains_live_uses_dns_qname_hint() {
        use chrono::{TimeZone, Utc};

        let mk = |idx: usize, qname: &str, rcode: Option<u16>| PacketRow {
            index: idx,
            ts: Utc.timestamp_opt(0, 0).unwrap(),
            len: 60,
            src: Some("10.0.0.2".parse().unwrap()),
            dst: Some("1.1.1.1".parse().unwrap()),
            proto: Some(L4Proto::Udp),
            src_port: Some(55555),
            dst_port: Some(53),
            summary: String::new(),
            flow: Some(crate::pcap::FlowKey {
                src: "10.0.0.2".parse().unwrap(),
                dst: "1.1.1.1".parse().unwrap(),
                src_port: 55555,
                dst_port: 53,
                proto: L4Proto::Udp,
            }),
            flow_dir: Some(crate::pcap::FlowDir::AtoB),
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            payload: Vec::new(),
            tcp_retransmission: false,
            tcp_out_of_order: false,
            dns_qname: Some(qname.to_string()),
            dns_rcode: rcode,
            http_host: None,
            tls_sni: None,
            tls_version: None,
        };

        let rows = vec![mk(0, "live.example", Some(3)), mk(1, "ok.example", Some(0))];
        let flows = crate::flow::FlowIndex::build(&rows);
        let dom = build_domains_summary(&rows, &flows, DomainsSort::Failures);

        assert_eq!(dom.items.first().unwrap().domain, "live.example");
        assert!(dom.items.first().unwrap().stats.failures >= 1);
    }

    #[test]
    fn domains_sort_by_failures() {
        use chrono::{TimeZone, Utc};

        let mk_dns = |idx: usize, qname: &str, rcode: u8| PacketRow {
            index: idx,
            ts: Utc.timestamp_opt(0, 0).unwrap(),
            len: 60,
            src: Some("1.1.1.1".parse().unwrap()),
            dst: Some("10.0.0.2".parse().unwrap()),
            proto: Some(L4Proto::Udp),
            src_port: Some(53),
            dst_port: Some(55555),
            summary: String::new(),
            flow: Some(crate::pcap::FlowKey {
                src: "1.1.1.1".parse().unwrap(),
                dst: "10.0.0.2".parse().unwrap(),
                src_port: 53,
                dst_port: 55555,
                proto: L4Proto::Udp,
            }),
            flow_dir: Some(crate::pcap::FlowDir::BtoA),
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            payload: make_dns_response(qname, rcode),
            tcp_retransmission: false,
            tcp_out_of_order: false,
            dns_qname: None,
            dns_rcode: None,
            http_host: None,
            tls_sni: None,
            tls_version: None,
        };

        // a.com: 2 failures; b.com: 0 failures.
        let rows = vec![
            mk_dns(0, "a.com", 3),
            mk_dns(1, "a.com", 2),
            mk_dns(2, "b.com", 0),
        ];
        let flows = crate::flow::FlowIndex::build(&rows);
        let dom = build_domains_summary(&rows, &flows, DomainsSort::Failures);

        assert_eq!(dom.items.first().unwrap().domain, "a.com");
        assert!(dom.items.first().unwrap().stats.failures >= 2);
    }

    fn make_dns_response(qname: &str, rcode: u8) -> Vec<u8> {
        // Minimal DNS response with qdcount=1, ancount=0.
        // flags: 0x8000 (response) | rcode
        let flags: u16 = 0x8000 | (rcode as u16);
        let mut b: Vec<u8> = vec![
            0x00, 0x01, // id
            (flags >> 8) as u8,
            (flags & 0xff) as u8,
            0x00, 0x01, // qdcount
            0x00, 0x00, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
        ];

        for part in qname.split('.') {
            b.push(part.len() as u8);
            b.extend_from_slice(part.as_bytes());
        }
        b.push(0);
        // qtype A, qclass IN
        b.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        b
    }
}
