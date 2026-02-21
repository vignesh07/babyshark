use crate::pcap::{FlowKey, L4Proto, PacketRow};
use std::collections::HashMap;
use std::net::IpAddr;

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
