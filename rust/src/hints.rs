use crate::pcap::PacketRow;

/// Best-effort payload parsing to populate PacketRow hint fields.
///
/// This is intentionally conservative: if parsing fails, we leave hints as None.
pub fn populate_hints(row: &mut PacketRow) {
    if row.dns_qname.is_none() {
        row.dns_qname = parse_dns_qname(&row.payload);
    }
    if row.dns_rcode.is_none() {
        row.dns_rcode = parse_dns_rcode(&row.payload);
    }
    if row.http_host.is_none() {
        row.http_host = parse_http_host(&row.payload);
    }
    if row.tls_sni.is_none() {
        row.tls_sni = parse_tls_sni(&row.payload);
    }
}

fn parse_http_host(payload: &[u8]) -> Option<String> {
    // Super light: look for an HTTP request line and Host header in the same segment.
    // This will miss cases where headers are split across TCP segments.
    let s = std::str::from_utf8(payload).ok()?;
    if !(s.starts_with("GET ")
        || s.starts_with("POST ")
        || s.starts_with("HEAD ")
        || s.starts_with("PUT ")
        || s.starts_with("DELETE ")
        || s.starts_with("OPTIONS ")
        || s.starts_with("CONNECT "))
    {
        return None;
    }

    for line in s.split("\r\n") {
        let l = line.trim();
        if l.len() < 6 {
            continue;
        }
        if l.to_ascii_lowercase().starts_with("host:") {
            let host = l[5..].trim();
            if host.is_empty() {
                return None;
            }
            // Strip port if present.
            let host = host.split(':').next().unwrap_or(host).trim();
            if host.is_empty() {
                return None;
            }
            return Some(host.to_ascii_lowercase());
        }
    }
    None
}

fn parse_dns_qname(payload: &[u8]) -> Option<String> {
    // Minimal DNS header + first QNAME. Matches what domains.rs does, but returns just the qname.
    if payload.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    if qdcount == 0 {
        return None;
    }
    let (name, _off) = read_dns_name(payload, 12, 0)?;
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn parse_dns_rcode(payload: &[u8]) -> Option<u16> {
    // DNS header flags: QR is bit15; RCODE is low 4 bits.
    if payload.len() < 4 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = (flags & 0x8000) != 0;
    if !is_response {
        return None;
    }
    Some(flags & 0x000f)
}

fn read_dns_name(buf: &[u8], mut off: usize, depth: usize) -> Option<(String, usize)> {
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

        if (len & 0b1100_0000) == 0b1100_0000 {
            if off + 1 >= buf.len() {
                return None;
            }
            let ptr = (((len as u16 & 0x3f) << 8) | buf[off + 1] as u16) as usize;
            let (name, _end) = read_dns_name(buf, ptr, depth + 1)?;
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

fn parse_tls_sni(payload: &[u8]) -> Option<String> {
    // Minimal TLS ClientHello SNI parse.
    // Supports a single TLS record containing handshake.
    if payload.len() < 5 {
        return None;
    }

    // TLS record header
    let content_type = payload[0];
    if content_type != 22 {
        return None; // handshake
    }
    let _ver = u16::from_be_bytes([payload[1], payload[2]]);
    let rec_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + rec_len {
        return None;
    }
    let mut off = 5;

    // Handshake header
    if off + 4 > payload.len() {
        return None;
    }
    let hs_type = payload[off];
    if hs_type != 1 {
        return None; // ClientHello
    }
    let hs_len = ((payload[off + 1] as usize) << 16)
        | ((payload[off + 2] as usize) << 8)
        | (payload[off + 3] as usize);
    off += 4;
    if off + hs_len > payload.len() {
        return None;
    }

    // ClientHello
    if off + 2 + 32 > payload.len() {
        return None;
    }
    off += 2; // client version
    off += 32; // random

    // session id
    if off + 1 > payload.len() {
        return None;
    }
    let sid_len = payload[off] as usize;
    off += 1 + sid_len;
    if off + 2 > payload.len() {
        return None;
    }

    // cipher suites
    let cs_len = u16::from_be_bytes([payload[off], payload[off + 1]]) as usize;
    off += 2 + cs_len;
    if off + 1 > payload.len() {
        return None;
    }

    // compression
    let comp_len = payload[off] as usize;
    off += 1 + comp_len;
    if off + 2 > payload.len() {
        return None;
    }

    // extensions
    let ext_len = u16::from_be_bytes([payload[off], payload[off + 1]]) as usize;
    off += 2;
    if off + ext_len > payload.len() {
        return None;
    }

    let ext_end = off + ext_len;
    while off + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[off], payload[off + 1]]);
        let e_len = u16::from_be_bytes([payload[off + 2], payload[off + 3]]) as usize;
        off += 4;
        if off + e_len > ext_end {
            break;
        }

        if ext_type == 0x0000 {
            // server_name
            if e_len < 2 {
                return None;
            }
            let list_len = u16::from_be_bytes([payload[off], payload[off + 1]]) as usize;
            let mut p = off + 2;
            let list_end = (off + 2 + list_len).min(off + e_len);
            while p + 3 <= list_end {
                let name_type = payload[p];
                let nlen = u16::from_be_bytes([payload[p + 1], payload[p + 2]]) as usize;
                p += 3;
                if p + nlen > list_end {
                    break;
                }
                if name_type == 0 {
                    let host = std::str::from_utf8(&payload[p..p + nlen]).ok()?;
                    let host = host.trim().to_ascii_lowercase();
                    if !host.is_empty() {
                        return Some(host);
                    }
                }
                p += nlen;
            }
        }

        off += e_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap::PacketRow;

    #[test]
    fn http_host_is_extracted() {
        let p = b"GET / HTTP/1.1\r\nHost: Example.COM:443\r\n\r\n";
        assert_eq!(parse_http_host(p).as_deref(), Some("example.com"));
    }

    #[test]
    fn dns_qname_empty_when_not_dns() {
        assert_eq!(parse_dns_qname(b"not dns"), None);
    }

    #[test]
    fn dns_rcode_parses_nxdomain() {
        // Minimal DNS response with rcode=3 (NXDOMAIN) and qdcount=1.
        // flags = 0x8183: response + recursion available + NXDOMAIN
        let p: Vec<u8> = vec![
            0x00, 0x01, // id
            0x81, 0x83, // flags
            0x00, 0x01, // qdcount
            0x00, 0x00, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
            // qname: a.com
            0x01, b'a', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, // qtype A
            0x00, 0x01, // qclass IN
        ];

        let mut row = PacketRow {
            index: 0,
            ts: chrono::Utc::now(),
            len: p.len(),
            src: None,
            dst: None,
            proto: None,
            src_port: None,
            dst_port: None,
            summary: String::new(),
            flow: None,
            flow_dir: None,
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            payload: p.clone(),
            tcp_retransmission: false,
            tcp_out_of_order: false,
            dns_qname: None,
            dns_rcode: None,
            http_host: None,
            tls_sni: None,
        };

        populate_hints(&mut row);
        assert_eq!(row.dns_qname.as_deref(), Some("a.com"));
        assert_eq!(row.dns_rcode, Some(3));

        // sanity: direct parser agrees
        assert_eq!(parse_dns_rcode(&p), Some(3));
    }
}
