use crate::pcap::{FlowDir, PacketRow};
use crate::flow::FlowStats;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamData {
    pub a_to_b: Vec<u8>,
    pub b_to_a: Vec<u8>,
}

/// Best-effort stream reconstruction.
///
/// For now this is **not** full TCP reassembly: it concatenates payloads in capture order
/// for the selected flow. Good enough for an MVP "follow stream" and tests.
pub fn build_stream(rows: &[PacketRow], flow: &FlowStats) -> StreamData {
    let mut out = StreamData::default();

    for idx in &flow.packet_indices {
        let Some(r) = rows.get(*idx) else { continue };
        if r.payload.is_empty() {
            continue;
        }
        match r.flow_dir {
            Some(FlowDir::AtoB) => out.a_to_b.extend_from_slice(&r.payload),
            Some(FlowDir::BtoA) => out.b_to_a.extend_from_slice(&r.payload),
            None => {}
        }
    }

    out
}
