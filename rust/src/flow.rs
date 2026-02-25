use crate::pcap::{FlowKey, L4Proto, PacketRow};
use std::collections::HashMap;
use std::net::IpAddr;

// TCP flag masks (same values as weird.rs).
const TCP_FLAG_FIN: u16 = 0x01;
const TCP_FLAG_SYN: u16 = 0x02;
const TCP_FLAG_RST: u16 = 0x04;
const TCP_FLAG_ACK: u16 = 0x10;

// ── Flow-level analysis types ────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthBadge {
    Green,
    Yellow,
    Red,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsymmetryLabel {
    AtoBHeavy,
    BtoAHeavy,
    Balanced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpTiming {
    /// SYN → SYN-ACK delta in microseconds.
    pub handshake_rtt_us: Option<i64>,
    /// SYN-ACK → first data packet in microseconds.
    pub server_think_us: Option<i64>,
    /// First data → last data in microseconds.
    pub data_transfer_us: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowAnalysis {
    pub health: HealthBadge,
    pub asymmetry: AsymmetryLabel,
    pub tcp_timing: Option<TcpTiming>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirStats {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowStats {
    pub key: FlowKey, // canonical
    pub total_packets: u64,
    pub total_bytes: u64,
    pub a_to_b: DirStats,
    pub b_to_a: DirStats,
    pub packet_indices: Vec<usize>,
    pub analysis: Option<FlowAnalysis>,
    pub first_ts: Option<chrono::DateTime<chrono::Utc>>,
    pub last_ts: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for FlowStats {
    fn default() -> Self {
        // Placeholder key; overwritten on creation.
        FlowStats {
            key: FlowKey {
                src: std::net::IpAddr::from([0, 0, 0, 0]),
                dst: std::net::IpAddr::from([0, 0, 0, 0]),
                src_port: 0,
                dst_port: 0,
                proto: crate::pcap::L4Proto::Other(0),
            },
            total_packets: 0,
            total_bytes: 0,
            a_to_b: DirStats::default(),
            b_to_a: DirStats::default(),
            packet_indices: Vec::new(),
            analysis: None,
            first_ts: None,
            last_ts: None,
        }
    }
}

impl FlowStats {
    pub fn label(&self) -> String {
        let proto = match self.key.proto {
            L4Proto::Tcp => "TCP",
            L4Proto::Udp => "UDP",
            L4Proto::Other(_) => "L4",
        };
        format!(
            "{proto} {}:{} ↔ {}:{}",
            self.key.src, self.key.src_port, self.key.dst, self.key.dst_port
        )
    }

    pub fn asymmetry_compact_suffix(&self) -> Option<&'static str> {
        let analysis = self.analysis.as_ref()?;
        match analysis.asymmetry {
            AsymmetryLabel::Balanced => None,
            AsymmetryLabel::AtoBHeavy => Some(match infer_local_side(self.key.src, self.key.dst) {
                Some(LocalSide::A) => "UL",
                Some(LocalSide::B) => "DL",
                None => "A>B",
            }),
            AsymmetryLabel::BtoAHeavy => Some(match infer_local_side(self.key.src, self.key.dst) {
                Some(LocalSide::A) => "DL",
                Some(LocalSide::B) => "UL",
                None => "B>A",
            }),
        }
    }

    pub fn asymmetry_detail_label(&self) -> Option<&'static str> {
        let analysis = self.analysis.as_ref()?;
        Some(match analysis.asymmetry {
            AsymmetryLabel::Balanced => "balanced",
            AsymmetryLabel::AtoBHeavy => match infer_local_side(self.key.src, self.key.dst) {
                Some(LocalSide::A) => "upload-heavy",
                Some(LocalSide::B) => "download-heavy",
                None => "A->B-heavy",
            },
            AsymmetryLabel::BtoAHeavy => match infer_local_side(self.key.src, self.key.dst) {
                Some(LocalSide::A) => "download-heavy",
                Some(LocalSide::B) => "upload-heavy",
                None => "B->A-heavy",
            },
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalSide {
    A,
    B,
}

fn infer_local_side(a: IpAddr, b: IpAddr) -> Option<LocalSide> {
    let a_local = is_likely_local_ip(a);
    let b_local = is_likely_local_ip(b);
    match (a_local, b_local) {
        (true, false) => Some(LocalSide::A),
        (false, true) => Some(LocalSide::B),
        _ => None,
    }
}

fn is_likely_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let is_cgnat = o[0] == 100 && (64..=127).contains(&o[1]);
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || is_cgnat
        }
        IpAddr::V6(v6) => v6.is_unique_local() || v6.is_loopback() || v6.is_unicast_link_local(),
    }
}

#[derive(Debug, Clone, Default)]
pub struct FlowIndex {
    pub flows: Vec<FlowStats>,
}

impl FlowIndex {
    pub fn build(rows: &[PacketRow]) -> FlowIndex {
        let mut map: HashMap<FlowKey, FlowStats> = HashMap::new();

        for r in rows {
            let Some(flow) = &r.flow else { continue };
            let (canon, flipped) = flow.canonical();

            let entry = map.entry(canon.clone()).or_insert_with(|| FlowStats {
                key: canon.clone(),
                ..Default::default()
            });

            entry.total_packets += 1;
            entry.total_bytes += r.len as u64;

            if flipped {
                entry.b_to_a.packets += 1;
                entry.b_to_a.bytes += r.len as u64;
            } else {
                entry.a_to_b.packets += 1;
                entry.a_to_b.bytes += r.len as u64;
            }

            entry.packet_indices.push(r.index);
        }

        let mut flows: Vec<FlowStats> = map.into_values().collect();

        // Derive first/last timestamps from packet_indices (which are in row order = time order).
        for fl in flows.iter_mut() {
            if let Some(&first) = fl.packet_indices.first() {
                if let Some(r) = rows.get(first) {
                    fl.first_ts = Some(r.ts);
                }
            }
            if let Some(&last) = fl.packet_indices.last() {
                if let Some(r) = rows.get(last) {
                    fl.last_ts = Some(r.ts);
                }
            }
        }
        // deterministic ordering: by total_bytes desc, then key
        flows.sort_by(|a, b| {
            b.total_bytes
                .cmp(&a.total_bytes)
                .then_with(|| a.key.src.cmp(&b.key.src))
                .then_with(|| a.key.src_port.cmp(&b.key.src_port))
                .then_with(|| a.key.dst.cmp(&b.key.dst))
                .then_with(|| a.key.dst_port.cmp(&b.key.dst_port))
        });

        FlowIndex { flows }
    }

    pub fn by_endpoints(&self, a: IpAddr, b: IpAddr) -> Vec<&FlowStats> {
        self.flows
            .iter()
            .filter(|f| (f.key.src == a && f.key.dst == b) || (f.key.src == b && f.key.dst == a))
            .collect()
    }
}

// ── Per-flow analysis ────────────────────────────────────────────────────

/// Compute health badges, asymmetry labels, and TCP timing for every flow.
pub fn analyze_flows(flows: &mut FlowIndex, rows: &[PacketRow]) {
    for fl in flows.flows.iter_mut() {
        let health = compute_health(fl, rows);
        let asymmetry = compute_asymmetry(fl);
        let tcp_timing = compute_tcp_timing(fl, rows);
        fl.analysis = Some(FlowAnalysis {
            health,
            asymmetry,
            tcp_timing,
        });
    }
}

fn compute_health(fl: &FlowStats, rows: &[PacketRow]) -> HealthBadge {
    if fl.key.proto != L4Proto::Tcp {
        return HealthBadge::Green;
    }

    let mut has_rst = false;
    let mut syn_count = 0u32;
    let mut syn_ack_count = 0u32;
    let mut has_retransmit = false;

    for &pi in &fl.packet_indices {
        let Some(r) = rows.get(pi) else { continue };
        let flags = r.tcp_flags.unwrap_or(0);

        if (flags & TCP_FLAG_RST) != 0 {
            has_rst = true;
        }
        if (flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) == 0 {
            syn_count += 1;
        }
        if (flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) != 0 {
            syn_ack_count += 1;
        }
        if r.tcp_retransmission || r.tcp_out_of_order {
            has_retransmit = true;
        }
    }

    // Red: connection refused/aborted (RST) or handshake never completed.
    if has_rst {
        return HealthBadge::Red;
    }
    if syn_count >= 2 && syn_ack_count == 0 {
        return HealthBadge::Red;
    }

    // Yellow: retransmissions or out-of-order segments.
    if has_retransmit {
        return HealthBadge::Yellow;
    }

    HealthBadge::Green
}

fn compute_asymmetry(fl: &FlowStats) -> AsymmetryLabel {
    let total = fl.a_to_b.bytes + fl.b_to_a.bytes;
    if total == 0 {
        return AsymmetryLabel::Balanced;
    }
    let a_frac = (fl.a_to_b.bytes as f64) / (total as f64);
    if a_frac > 0.70 {
        AsymmetryLabel::AtoBHeavy
    } else if a_frac < 0.30 {
        AsymmetryLabel::BtoAHeavy
    } else {
        AsymmetryLabel::Balanced
    }
}

fn compute_tcp_timing(fl: &FlowStats, rows: &[PacketRow]) -> Option<TcpTiming> {
    if fl.key.proto != L4Proto::Tcp {
        return None;
    }

    let mut syn_ts: Option<chrono::DateTime<chrono::Utc>> = None;
    let mut syn_ack_ts: Option<chrono::DateTime<chrono::Utc>> = None;
    let mut first_data_ts: Option<chrono::DateTime<chrono::Utc>> = None;
    let mut last_data_ts: Option<chrono::DateTime<chrono::Utc>> = None;

    for &pi in &fl.packet_indices {
        let Some(r) = rows.get(pi) else { continue };
        let flags = r.tcp_flags.unwrap_or(0);

        let is_syn = (flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) == 0;
        let is_syn_ack = (flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) != 0;
        let is_pure_control = (flags & TCP_FLAG_SYN) != 0
            || (flags & TCP_FLAG_FIN) != 0
            || (flags & TCP_FLAG_RST) != 0;

        if is_syn && syn_ts.is_none() {
            syn_ts = Some(r.ts);
        }
        if is_syn_ack && syn_ack_ts.is_none() {
            syn_ack_ts = Some(r.ts);
        }
        // "Data" = not a pure SYN/FIN/RST and has payload.
        if !is_pure_control && !r.payload.is_empty() {
            if first_data_ts.is_none() {
                first_data_ts = Some(r.ts);
            }
            last_data_ts = Some(r.ts);
        }
    }

    let handshake_rtt_us = match (syn_ts, syn_ack_ts) {
        (Some(s), Some(sa)) => {
            let d = (sa - s).num_microseconds();
            d.filter(|&v| v >= 0)
        }
        _ => None,
    };

    let server_think_us = match (syn_ack_ts, first_data_ts) {
        (Some(sa), Some(d)) => {
            let v = (d - sa).num_microseconds();
            v.filter(|&v| v >= 0)
        }
        _ => None,
    };

    let data_transfer_us = match (first_data_ts, last_data_ts) {
        (Some(f), Some(l)) if f != l => {
            let v = (l - f).num_microseconds();
            v.filter(|&v| v >= 0)
        }
        _ => None,
    };

    Some(TcpTiming {
        handshake_rtt_us,
        server_think_us,
        data_transfer_us,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap::{FlowDir, FlowKey};
    use chrono::{TimeZone, Utc};

    fn tcp_row(
        idx: usize,
        ms: i64,
        len: usize,
        sp: u16,
        dp: u16,
        flags: u16,
        payload_len: usize,
        retrans: bool,
    ) -> PacketRow {
        PacketRow {
            index: idx,
            ts: Utc.timestamp_millis_opt(ms).unwrap(),
            len,
            src: Some("10.0.0.1".parse().unwrap()),
            dst: Some("93.184.216.34".parse().unwrap()),
            proto: Some(L4Proto::Tcp),
            src_port: Some(sp),
            dst_port: Some(dp),
            summary: String::new(),
            flow: Some(FlowKey {
                src: "10.0.0.1".parse().unwrap(),
                dst: "93.184.216.34".parse().unwrap(),
                src_port: sp,
                dst_port: dp,
                proto: L4Proto::Tcp,
            }),
            flow_dir: Some(FlowDir::AtoB),
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: Some(flags),
            payload: vec![0u8; payload_len],
            tcp_retransmission: retrans,
            tcp_out_of_order: false,
            dns_qname: None,
            dns_rcode: None,
            http_host: None,
            tls_sni: None,
            tls_version: None,
        }
    }

    #[test]
    fn health_green_for_clean_tcp() {
        // SYN, SYN-ACK, data, FIN — no RST, no retransmits.
        let rows = vec![
            tcp_row(0, 0, 60, 1111, 80, TCP_FLAG_SYN, 0, false),
            tcp_row(1, 10, 60, 1111, 80, TCP_FLAG_SYN | TCP_FLAG_ACK, 0, false),
            tcp_row(2, 20, 500, 1111, 80, TCP_FLAG_ACK, 100, false),
            tcp_row(3, 100, 60, 1111, 80, TCP_FLAG_FIN | TCP_FLAG_ACK, 0, false),
        ];
        let mut flows = FlowIndex::build(&rows);
        analyze_flows(&mut flows, &rows);
        assert_eq!(
            flows.flows[0].analysis.as_ref().unwrap().health,
            HealthBadge::Green
        );
    }

    #[test]
    fn health_red_for_rst() {
        let rows = vec![
            tcp_row(0, 0, 60, 1111, 80, TCP_FLAG_SYN, 0, false),
            tcp_row(1, 10, 60, 1111, 80, TCP_FLAG_RST, 0, false),
        ];
        let mut flows = FlowIndex::build(&rows);
        analyze_flows(&mut flows, &rows);
        assert_eq!(
            flows.flows[0].analysis.as_ref().unwrap().health,
            HealthBadge::Red
        );
    }

    #[test]
    fn health_red_for_incomplete_handshake() {
        // Two SYNs, no SYN-ACK.
        let rows = vec![
            tcp_row(0, 0, 60, 1111, 80, TCP_FLAG_SYN, 0, false),
            tcp_row(1, 1000, 60, 1111, 80, TCP_FLAG_SYN, 0, false),
        ];
        let mut flows = FlowIndex::build(&rows);
        analyze_flows(&mut flows, &rows);
        assert_eq!(
            flows.flows[0].analysis.as_ref().unwrap().health,
            HealthBadge::Red
        );
    }

    #[test]
    fn health_yellow_for_retransmits() {
        let rows = vec![
            tcp_row(0, 0, 60, 1111, 80, TCP_FLAG_SYN, 0, false),
            tcp_row(1, 10, 60, 1111, 80, TCP_FLAG_SYN | TCP_FLAG_ACK, 0, false),
            tcp_row(2, 20, 500, 1111, 80, TCP_FLAG_ACK, 100, true), // retransmit
        ];
        let mut flows = FlowIndex::build(&rows);
        analyze_flows(&mut flows, &rows);
        assert_eq!(
            flows.flows[0].analysis.as_ref().unwrap().health,
            HealthBadge::Yellow
        );
    }

    #[test]
    fn asymmetry_b_to_a_heavy() {
        // a_to_b: 100 bytes, b_to_a: 900 bytes => B->A-heavy (a_frac = 0.1).
        let mut fl = FlowStats::default();
        fl.a_to_b = DirStats {
            packets: 1,
            bytes: 100,
        };
        fl.b_to_a = DirStats {
            packets: 9,
            bytes: 900,
        };
        assert_eq!(compute_asymmetry(&fl), AsymmetryLabel::BtoAHeavy);
    }

    #[test]
    fn asymmetry_a_to_b_heavy() {
        let mut fl = FlowStats::default();
        fl.a_to_b = DirStats {
            packets: 9,
            bytes: 900,
        };
        fl.b_to_a = DirStats {
            packets: 1,
            bytes: 100,
        };
        assert_eq!(compute_asymmetry(&fl), AsymmetryLabel::AtoBHeavy);
    }

    #[test]
    fn asymmetry_balanced() {
        let mut fl = FlowStats::default();
        fl.a_to_b = DirStats {
            packets: 5,
            bytes: 500,
        };
        fl.b_to_a = DirStats {
            packets: 5,
            bytes: 500,
        };
        assert_eq!(compute_asymmetry(&fl), AsymmetryLabel::Balanced);
    }

    #[test]
    fn asymmetry_labels_use_dl_ul_when_local_side_is_inferred() {
        let mut fl = FlowStats::default();
        fl.key = FlowKey {
            src: "10.0.0.2".parse().unwrap(),      // local
            dst: "93.184.216.34".parse().unwrap(), // remote
            src_port: 50000,
            dst_port: 443,
            proto: L4Proto::Tcp,
        };
        fl.analysis = Some(FlowAnalysis {
            health: HealthBadge::Green,
            asymmetry: AsymmetryLabel::AtoBHeavy,
            tcp_timing: None,
        });
        assert_eq!(fl.asymmetry_compact_suffix(), Some("UL"));
        assert_eq!(fl.asymmetry_detail_label(), Some("upload-heavy"));

        fl.analysis = Some(FlowAnalysis {
            health: HealthBadge::Green,
            asymmetry: AsymmetryLabel::BtoAHeavy,
            tcp_timing: None,
        });
        assert_eq!(fl.asymmetry_compact_suffix(), Some("DL"));
        assert_eq!(fl.asymmetry_detail_label(), Some("download-heavy"));
    }

    #[test]
    fn asymmetry_labels_fallback_to_a_b_when_local_side_ambiguous() {
        let mut fl = FlowStats::default();
        fl.key = FlowKey {
            src: "93.184.216.34".parse().unwrap(),
            dst: "198.51.100.42".parse().unwrap(),
            src_port: 443,
            dst_port: 50000,
            proto: L4Proto::Tcp,
        };
        fl.analysis = Some(FlowAnalysis {
            health: HealthBadge::Green,
            asymmetry: AsymmetryLabel::AtoBHeavy,
            tcp_timing: None,
        });
        assert_eq!(fl.asymmetry_compact_suffix(), Some("A>B"));
        assert_eq!(fl.asymmetry_detail_label(), Some("A->B-heavy"));
    }

    #[test]
    fn tcp_timing_extraction() {
        let rows = vec![
            tcp_row(0, 0, 60, 1111, 80, TCP_FLAG_SYN, 0, false), // t=0
            tcp_row(1, 50, 60, 1111, 80, TCP_FLAG_SYN | TCP_FLAG_ACK, 0, false), // t=50ms
            tcp_row(2, 80, 500, 1111, 80, TCP_FLAG_ACK, 100, false), // t=80ms, first data
            tcp_row(3, 200, 500, 1111, 80, TCP_FLAG_ACK, 100, false), // t=200ms, last data
        ];
        let mut flows = FlowIndex::build(&rows);
        analyze_flows(&mut flows, &rows);

        let timing = flows.flows[0]
            .analysis
            .as_ref()
            .unwrap()
            .tcp_timing
            .unwrap();
        assert_eq!(timing.handshake_rtt_us, Some(50_000)); // 50ms
        assert_eq!(timing.server_think_us, Some(30_000)); // 30ms
        assert_eq!(timing.data_transfer_us, Some(120_000)); // 120ms
    }

    #[test]
    fn tcp_timing_none_for_udp() {
        let row = PacketRow {
            index: 0,
            ts: Utc::now(),
            len: 60,
            src: Some("10.0.0.1".parse().unwrap()),
            dst: Some("1.1.1.1".parse().unwrap()),
            proto: Some(L4Proto::Udp),
            src_port: Some(55555),
            dst_port: Some(53),
            summary: String::new(),
            flow: Some(FlowKey {
                src: "10.0.0.1".parse().unwrap(),
                dst: "1.1.1.1".parse().unwrap(),
                src_port: 55555,
                dst_port: 53,
                proto: L4Proto::Udp,
            }),
            flow_dir: Some(FlowDir::AtoB),
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            payload: Vec::new(),
            tcp_retransmission: false,
            tcp_out_of_order: false,
            dns_qname: None,
            dns_rcode: None,
            http_host: None,
            tls_sni: None,
            tls_version: None,
        };
        let mut flows = FlowIndex::build(&[row]);
        analyze_flows(&mut flows, &[]);
        assert!(flows.flows[0]
            .analysis
            .as_ref()
            .unwrap()
            .tcp_timing
            .is_none());
    }

    #[test]
    fn first_last_ts_set_after_build() {
        let rows = vec![
            tcp_row(0, 100, 60, 1111, 80, TCP_FLAG_SYN, 0, false),
            tcp_row(1, 200, 60, 1111, 80, TCP_FLAG_SYN | TCP_FLAG_ACK, 0, false),
            tcp_row(2, 500, 500, 1111, 80, TCP_FLAG_ACK, 100, false),
        ];
        let flows = FlowIndex::build(&rows);
        assert_eq!(flows.flows.len(), 1);
        let fl = &flows.flows[0];
        assert_eq!(fl.first_ts, Some(Utc.timestamp_millis_opt(100).unwrap()));
        assert_eq!(fl.last_ts, Some(Utc.timestamp_millis_opt(500).unwrap()));
    }

    #[test]
    fn first_last_ts_single_packet() {
        let rows = vec![tcp_row(0, 42, 60, 1111, 80, TCP_FLAG_SYN, 0, false)];
        let flows = FlowIndex::build(&rows);
        let fl = &flows.flows[0];
        assert_eq!(fl.first_ts, fl.last_ts);
        assert!(fl.first_ts.is_some());
    }
}
