use crate::flow::FlowIndex;
use crate::pcap::{L4Proto, PacketRow};

const TCP_FLAG_FIN: u16 = 0x01;
const TCP_FLAG_SYN: u16 = 0x02;
const TCP_FLAG_RST: u16 = 0x04;
const TCP_FLAG_ACK: u16 = 0x10;

#[derive(Debug, Clone)]
pub struct WeirdItem {
    pub title: String,
    pub why: String,
    /// Indices into `FlowIndex.flows`.
    pub flow_indices: Vec<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct WeirdSummary {
    pub items: Vec<WeirdItem>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeirdDetector {
    TcpResets,
    TcpHandshakeNotCompleted,
}

fn row_has_tcp_flag(row: &PacketRow, flag: u16) -> bool {
    row.tcp_flags.map(|m| (m & flag) != 0).unwrap_or(false)
}

pub fn build_weird_summary(rows: &[PacketRow], flows: &FlowIndex) -> WeirdSummary {
    let mut out: Vec<WeirdItem> = Vec::new();

    // Detector: TCP resets (RST)
    {
        let mut flow_indices: Vec<usize> = Vec::new();
        for (i, fl) in flows.flows.iter().enumerate() {
            if fl.key.proto != L4Proto::Tcp {
                continue;
            }
            let mut has_rst = false;
            for pi in fl.packet_indices.iter().copied() {
                if let Some(r) = rows.get(pi) {
                    if row_has_tcp_flag(r, TCP_FLAG_RST) {
                        has_rst = true;
                        break;
                    }
                }
            }
            if has_rst {
                flow_indices.push(i);
            }
        }

        out.push(WeirdItem {
            title: "TCP resets (RST)".to_string(),
            why: "RST usually means a connection was refused/aborted. A few can be normal, but lots of RSTs often point to blocked ports, app crashes, or middleboxes terminating connections.".to_string(),
            flow_indices,
        });
    }

    // Detector: SYNs without SYN,ACK (very rough handshake-not-completed heuristic)
    {
        let mut flow_indices: Vec<usize> = Vec::new();
        for (i, fl) in flows.flows.iter().enumerate() {
            if fl.key.proto != L4Proto::Tcp {
                continue;
            }

            let mut syn = 0u32;
            let mut syn_ack = 0u32;
            let mut fin = 0u32;

            for pi in fl.packet_indices.iter().copied() {
                let Some(r) = rows.get(pi) else { continue };
                let Some(flags) = r.tcp_flags else { continue };

                if (flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) == 0 {
                    syn += 1;
                }
                if (flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) != 0 {
                    syn_ack += 1;
                }
                if (flags & TCP_FLAG_FIN) != 0 {
                    fin += 1;
                }
            }

            // Heuristic: we saw outbound SYNs but never saw a SYN,ACK in this flow.
            // (This can also happen if capture is one-sided.)
            if syn >= 2 && syn_ack == 0 && fin == 0 {
                flow_indices.push(i);
            }
        }

        out.push(WeirdItem {
            title: "Handshake not completed".to_string(),
            why: "Repeated SYNs without a SYN,ACK often means the server didn’t respond (dropped packets, firewall), or the capture missed the return path. If these line up with user complaints, it’s a strong lead.".to_string(),
            flow_indices,
        });
    }

    // Sort: most interesting first.
    out.sort_by_key(|it| std::cmp::Reverse(it.flow_indices.len()));

    WeirdSummary { items: out }
}
