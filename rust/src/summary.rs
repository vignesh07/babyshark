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

    /// Coarse packets-per-second buckets for a tiny sparkline in the Overview.
    ///
    /// We pick a bucket width such that we produce at most ~30 buckets.
    pub pps_buckets: Vec<u32>,

    pub top_ports: Vec<(u16, HostCounts)>,

    /// Sorted by total bytes (desc).
    pub top_hosts: Vec<(IpAddr, HostCounts)>,
    /// Sorted by total packets (desc).
    pub top_hosts_by_packets: Vec<(IpAddr, HostCounts)>,

    /// Sorted by total bytes (desc).
    pub top_flows: Vec<FlowStats>,
    /// Sorted by total packets (desc).
    pub top_flows_by_packets: Vec<FlowStats>,
}

fn bump(m: &mut HashMap<u64, HostCounts>, k: u64, bytes: u64) {
    let e = m.entry(k).or_default();
    e.packets += 1;
    e.bytes += bytes;
}

fn build_pps_buckets(rows: &[PacketRow]) -> Vec<u32> {
    // Keep it simple and stable: we bucket by wall-clock deltas within the capture.
    // If timestamps are missing or only a single packet, return an empty sparkline.
    let first = rows.first().map(|r| r.ts);
    let last = rows.last().map(|r| r.ts);
    let (Some(start), Some(end)) = (first, last) else {
        return Vec::new();
    };

    let mut duration_s = (end - start).num_seconds();
    if duration_s < 0 {
        duration_s = 0;
    }

    // If everything happened at the same second, don’t pretend we have a time-series.
    if duration_s == 0 {
        return Vec::new();
    }

    // Aim for <= 30 buckets (coarse), with at least 1s bucket width.
    let bucket_width_s: i64 = ((duration_s as f64) / 30.0).ceil() as i64;
    let bucket_width_s = bucket_width_s.max(1);

    // Duration is delta between first/last timestamps. For inclusive bucketing, we need +1 bucket.
    let max_dt_s = duration_s;
    let bucket_count: usize = ((max_dt_s / bucket_width_s) + 1) as usize;

    let mut buckets = vec![0u32; bucket_count.max(1)];

    for r in rows {
        let dt = (r.ts - start).num_seconds();
        if dt < 0 {
            continue;
        }
        let idx = (dt / bucket_width_s) as usize;
        if let Some(b) = buckets.get_mut(idx) {
            *b = b.saturating_add(1);
        }
    }

    // Trim trailing zeros so the UI doesn’t draw a flat tail.
    while buckets.last().is_some_and(|v| *v == 0) {
        buckets.pop();
    }

    buckets
}

pub fn build_overview(rows: &[PacketRow], flows: &FlowIndex, limit: usize) -> OverviewSummary {
    let limit = limit.max(1).min(50);

    let mut out = OverviewSummary::default();
    out.total_packets = rows.len();
    out.pps_buckets = build_pps_buckets(rows);

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

    let mut top_hosts: Vec<(IpAddr, HostCounts)> = hosts
        .into_iter()
        .filter_map(|(k, v)| u64_to_ip(k).map(|ip| (ip, v)))
        .collect();

    top_hosts.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes).then_with(|| b.1.packets.cmp(&a.1.packets)));
    out.top_hosts = top_hosts.clone();
    out.top_hosts.truncate(limit);

    top_hosts.sort_by(|a, b| b.1.packets.cmp(&a.1.packets).then_with(|| b.1.bytes.cmp(&a.1.bytes)));
    out.top_hosts_by_packets = top_hosts;
    out.top_hosts_by_packets.truncate(limit);

    // FlowIndex is already sorted by total_bytes desc.
    out.top_flows = flows.flows.iter().take(limit).cloned().collect();

    let mut by_packets: Vec<FlowStats> = flows.flows.iter().cloned().collect();
    by_packets.sort_by(|a, b| {
        b.total_packets
            .cmp(&a.total_packets)
            .then_with(|| b.total_bytes.cmp(&a.total_bytes))
    });
    by_packets.truncate(limit);
    out.top_flows_by_packets = by_packets;

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
        // Fixture is tiny; pps buckets may be empty (same-second capture), but should never panic.

        // ports should include 80 and 1234
        let ports: Vec<u16> = ov.top_ports.iter().map(|p| p.0).collect();
        assert!(ports.contains(&80));
        assert!(ports.contains(&1234));

        // top flows should include the single flow
        assert_eq!(ov.top_flows.len(), 1);
        assert_eq!(ov.top_flows[0].key.proto, L4Proto::Tcp);

        // New: top talkers by packets should be present (even if order is trivial here).
        assert!(!ov.top_hosts_by_packets.is_empty());

        // New: top flows by packets should be present.
        assert!(!ov.top_flows_by_packets.is_empty());
    }

    #[test]
    fn pps_buckets_are_coarse_and_stable() {
        use chrono::{TimeZone, Utc};

        let mk = |sec: i64| PacketRow {
            index: 0,
            ts: Utc.timestamp_opt(sec, 0).unwrap(),
            len: 60,
            src: None,
            dst: None,
            proto: Some(L4Proto::Tcp),
            src_port: None,
            dst_port: None,
            summary: String::new(),
            flow: None,
            flow_dir: None,
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            payload: Vec::new(),
            dns_qname: None,
            dns_rcode: None,
            http_host: None,
            tls_sni: None,
        };

        // 6 packets spread over ~3 seconds.
        let rows = vec![mk(0), mk(0), mk(1), mk(1), mk(2), mk(3)];
        let b = build_pps_buckets(&rows);
        assert_eq!(b, vec![2, 2, 1, 1]);
    }

    #[test]
    fn top_flows_by_packets_prefers_packet_count() {
        use chrono::{TimeZone, Utc};

        let mk = |idx: usize, sec: i64, len: usize, proto: L4Proto, sp: u16, dp: u16| PacketRow {
            index: idx,
            ts: Utc.timestamp_opt(sec, 0).unwrap(),
            len,
            src: Some("1.1.1.1".parse().unwrap()),
            dst: Some("2.2.2.2".parse().unwrap()),
            proto: Some(proto),
            src_port: Some(sp),
            dst_port: Some(dp),
            summary: String::new(),
            flow: Some(crate::pcap::FlowKey {
                src: "1.1.1.1".parse().unwrap(),
                dst: "2.2.2.2".parse().unwrap(),
                src_port: sp,
                dst_port: dp,
                proto,
            }),
            flow_dir: Some(crate::pcap::FlowDir::AtoB),
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            payload: Vec::new(),
            dns_qname: None,
            dns_rcode: None,
            http_host: None,
            tls_sni: None,
        };

        // Flow A: 5 small packets.
        let mut rows: Vec<PacketRow> = (0..5)
            .map(|i| mk(i, 0, 60, L4Proto::Tcp, 1111, 80))
            .collect();
        // Flow B: 2 large packets.
        rows.push(mk(5, 0, 1500, L4Proto::Tcp, 2222, 443));
        rows.push(mk(6, 0, 1500, L4Proto::Tcp, 2222, 443));

        let flows = FlowIndex::build(&rows);
        let ov = build_overview(&rows, &flows, 10);

        assert_eq!(ov.top_flows_by_packets[0].total_packets, 5);
        assert_eq!(ov.top_flows_by_packets[0].key.src_port, 1111);
    }
}
