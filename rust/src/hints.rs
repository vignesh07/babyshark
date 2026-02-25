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
    if row.tls_version.is_none() {
        row.tls_version = parse_tls_version(&row.payload);
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

fn parse_tls_version(payload: &[u8]) -> Option<u16> {
    // Extract TLS version from ServerHello when available.
    // For TLS 1.3 this reads the supported_versions extension (0x002b);
    // otherwise it falls back to ServerHello legacy_version.
    if payload.len() < 5 {
        return None;
    }
    if payload[0] != 22 {
        return None; // not a handshake record
    }
    let rec_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + rec_len {
        return None;
    }
    let rec_end = 5 + rec_len;
    let mut off = 5usize;

    // A record can carry multiple handshake messages.
    while off + 4 <= rec_end {
        let hs_type = payload[off];
        let hs_len = ((payload[off + 1] as usize) << 16)
            | ((payload[off + 2] as usize) << 8)
            | (payload[off + 3] as usize);
        off += 4;

        if off + hs_len > rec_end {
            break;
        }

        if hs_type == 2 {
            // ServerHello
            let hs = &payload[off..off + hs_len];
            if hs.len() < 2 + 32 + 1 + 2 + 1 {
                return None;
            }

            let legacy_version = u16::from_be_bytes([hs[0], hs[1]]);
            let mut p = 2 + 32; // legacy_version + random

            let sid_len = hs[p] as usize;
            p += 1;
            if p + sid_len > hs.len() {
                return None;
            }
            p += sid_len;

            if p + 2 + 1 > hs.len() {
                return None;
            }
            p += 2; // cipher_suite
            p += 1; // compression_method

            if p == hs.len() {
                return Some(legacy_version);
            }
            if p + 2 > hs.len() {
                return None;
            }
            let ext_len = u16::from_be_bytes([hs[p], hs[p + 1]]) as usize;
            p += 2;
            if p + ext_len > hs.len() {
                return None;
            }
            let ext_end = p + ext_len;
            while p + 4 <= ext_end {
                let ext_type = u16::from_be_bytes([hs[p], hs[p + 1]]);
                let e_len = u16::from_be_bytes([hs[p + 2], hs[p + 3]]) as usize;
                p += 4;
                if p + e_len > ext_end {
                    break;
                }
                if ext_type == 0x002b && e_len == 2 {
                    // TLS 1.3+ negotiated version.
                    return Some(u16::from_be_bytes([hs[p], hs[p + 1]]));
                }
                p += e_len;
            }

            return Some(legacy_version);
        }

        off += hs_len;
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
            0x01, b'a', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, // qtype A
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
            tls_version: None,
        };

        populate_hints(&mut row);
        assert_eq!(row.dns_qname.as_deref(), Some("a.com"));
        assert_eq!(row.dns_rcode, Some(3));

        // sanity: direct parser agrees
        assert_eq!(parse_dns_rcode(&p), Some(3));
    }

    #[test]
    fn tls_version_extracts_from_server_hello() {
        fn wrap_handshake(hs_type: u8, hs_body: &[u8]) -> Vec<u8> {
            let hs_len = hs_body.len();
            let rec_len = hs_len + 4;

            let mut out = Vec::with_capacity(5 + rec_len);
            // TLS record header
            out.push(22); // handshake
            out.extend_from_slice(&[0x03, 0x03]); // legacy record version
            out.extend_from_slice(&(rec_len as u16).to_be_bytes());
            // Handshake header
            out.push(hs_type);
            out.push(((hs_len >> 16) & 0xff) as u8);
            out.push(((hs_len >> 8) & 0xff) as u8);
            out.push((hs_len & 0xff) as u8);
            out.extend_from_slice(hs_body);
            out
        }

        // TLS 1.2-style ServerHello (no extensions; version from legacy_version).
        let mut sh12 = Vec::new();
        sh12.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS1.2
        sh12.extend_from_slice(&[0u8; 32]); // random
        sh12.push(0); // session id len
        sh12.extend_from_slice(&[0x13, 0x01]); // cipher
        sh12.push(0); // compression
        sh12.extend_from_slice(&[0x00, 0x00]); // ext len
        let p12 = wrap_handshake(2, &sh12); // ServerHello
        assert_eq!(parse_tls_version(&p12), Some(0x0303));

        // TLS 1.3-style ServerHello with supported_versions extension = 0x0304.
        let mut sh13 = Vec::new();
        sh13.extend_from_slice(&[0x03, 0x03]); // legacy_version stays 0x0303
        sh13.extend_from_slice(&[0u8; 32]); // random
        sh13.push(0); // session id len
        sh13.extend_from_slice(&[0x13, 0x01]); // cipher
        sh13.push(0); // compression
                      // extensions length = 6 bytes (type + len + value)
        sh13.extend_from_slice(&[0x00, 0x06]);
        // supported_versions extension
        sh13.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        let p13 = wrap_handshake(2, &sh13);
        assert_eq!(parse_tls_version(&p13), Some(0x0304));

        // ClientHello should not be treated as negotiated version.
        let ch = wrap_handshake(1, &[0u8; 34]);
        assert_eq!(parse_tls_version(&ch), None);

        assert_eq!(parse_tls_version(b"not tls"), None);
        assert_eq!(parse_tls_version(&[]), None);
    }
}
