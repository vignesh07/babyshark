use crate::flow::{FlowIndex, FlowStats};
use crate::pcap::{L4Proto, PacketRow};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtoCounts {
    pub tcp: u64,
    pub udp: u64,
    pub other: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostCounts {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OverviewSummary {
    pub total_packets: usize,
    pub total_bytes: u64,
    pub protos: ProtoCounts,
    pub top_ports: Vec<(u16, HostCounts)>,
    pub top_hosts: Vec<(IpAddr, HostCounts)>,
    pub top_flows: Vec<FlowStats>,
}

fn bump(m: &mut HashMap<u64, HostCounts>, k: u64, bytes: u64) {
    let e = m.entry(k).or_default();
    e.packets += 1;
    e.bytes += bytes;
}

pub fn build_overview(rows: &[PacketRow], flows: &FlowIndex, limit: usize) -> OverviewSummary {
    let limit = limit.max(1).min(50);

    let mut out = OverviewSummary::default();
    out.total_packets = rows.len();

    let mut ports: HashMap<u64, HostCounts> = HashMap::new();
    let mut hosts: HashMap<u64, HostCounts> = HashMap::new();

    for r in rows {
        out.total_bytes += r.len as u64;

        match r.proto {
            Some(L4Proto::Tcp) => out.protos.tcp += 1,
            Some(L4Proto::Udp) => out.protos.udp += 1,
            Some(L4Proto::Other(_)) | None => out.protos.other += 1,
        }

        let bytes = r.len as u64;

        if let Some(sp) = r.src_port {
            bump(&mut ports, sp as u64, bytes);
        }
        if let Some(dp) = r.dst_port {
            bump(&mut ports, dp as u64, bytes);
        }

        if let Some(src) = r.src {
            bump(&mut hosts, ip_to_u64(src), bytes);
        }
        if let Some(dst) = r.dst {
            bump(&mut hosts, ip_to_u64(dst), bytes);
        }
    }

    out.top_ports = ports
        .into_iter()
        .map(|(k, v)| (k as u16, v))
        .collect();
    out.top_ports.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes).then_with(|| b.1.packets.cmp(&a.1.packets)));
    out.top_ports.truncate(limit);

    out.top_hosts = hosts
        .into_iter()
        .filter_map(|(k, v)| u64_to_ip(k).map(|ip| (ip, v)))
        .collect();
    out.top_hosts.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes).then_with(|| b.1.packets.cmp(&a.1.packets)));
    out.top_hosts.truncate(limit);

    out.top_flows = flows.flows.iter().take(limit).cloned().collect();

    out
}

fn ip_to_u64(ip: IpAddr) -> u64 {
    match ip {
        IpAddr::V4(v4) => u32::from(v4) as u64,
        IpAddr::V6(v6) => {
            // lossy hash for now: keep stable ordering without allocating.
            let segs = v6.segments();
            let mut h: u64 = 1469598103934665603;
            for s in segs {
                h ^= s as u64;
                h = h.wrapping_mul(1099511628211);
            }
            h
        }
    }
}

fn u64_to_ip(k: u64) -> Option<IpAddr> {
    // We can only round-trip IPv4 keys. IPv6 uses a hash.
    if k <= u32::MAX as u64 {
        Some(IpAddr::V4((k as u32).into()))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::FlowIndex;
    use crate::pcap::{read_pcap, L4Proto};

    mod fixtures {
        include!("../tests/fixtures/mod.rs");
    }

    #[test]
    fn overview_counts_packets_ports_hosts() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        fixtures::write_two_tcp_packets(tmp.as_file_mut());

        let rows = read_pcap(tmp.path()).unwrap();
        let flows = FlowIndex::build(&rows);
        let ov = build_overview(&rows, &flows, 10);

        assert_eq!(ov.total_packets, 2);
        assert_eq!(ov.protos.tcp, 2);
        assert_eq!(ov.protos.udp, 0);

        // ports should include 80 and 1234
        let ports: Vec<u16> = ov.top_ports.iter().map(|p| p.0).collect();
        assert!(ports.contains(&80));
        assert!(ports.contains(&1234));

        // top flows should include the single flow
        assert_eq!(ov.top_flows.len(), 1);
        assert_eq!(ov.top_flows[0].key.proto, L4Proto::Tcp);
    }
}
