use crate::pcap::{FlowDir, L4Proto, PacketRow};
use crate::flow::FlowStats;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamData {
    pub a_to_b: Vec<u8>,
    pub b_to_a: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Segment<'a> {
    seq: u32,
    payload: &'a [u8],
}

fn reassemble(mut segs: Vec<Segment<'_>>) -> Vec<u8> {
    // Sort by sequence number, then append while avoiding duplicates/overlaps.
    segs.sort_by_key(|s| s.seq);

    let mut out: Vec<u8> = Vec::new();
    let mut next_seq: Option<u32> = None;

    for s in segs {
        if s.payload.is_empty() {
            continue;
        }
        match next_seq {
            None => {
                out.extend_from_slice(s.payload);
                next_seq = Some(s.seq.wrapping_add(s.payload.len() as u32));
            }
            Some(cur) => {
                if s.seq >= cur {
                    // Gap or exactly next.
                    // For MVP: if gap, just append; later we can annotate gaps.
                    out.extend_from_slice(s.payload);
                    next_seq = Some(s.seq.wrapping_add(s.payload.len() as u32));
                } else {
                    // Overlap/duplicate.
                    let overlap = (cur - s.seq) as usize;
                    if overlap < s.payload.len() {
                        out.extend_from_slice(&s.payload[overlap..]);
                        next_seq = Some(cur.wrapping_add((s.payload.len() - overlap) as u32));
                    }
                }
            }
        }
    }

    out
}

/// Stream reconstruction.
///
/// - For TCP: best-effort reassembly by sequence number (no retransmit timing logic, but handles out-of-order and overlap).
/// - For UDP/other: concatenates payloads in capture order.
pub fn build_stream(rows: &[PacketRow], flow: &FlowStats) -> StreamData {
    let is_tcp = flow.key.proto == L4Proto::Tcp;

    if is_tcp {
        let mut ab: Vec<Segment<'_>> = Vec::new();
        let mut ba: Vec<Segment<'_>> = Vec::new();

        for idx in &flow.packet_indices {
            let Some(r) = rows.get(*idx) else { continue };
            if r.payload.is_empty() {
                continue;
            }
            let Some(seq) = r.tcp_seq else {
                // If no seq, fall back to simple concatenation later.
                continue;
            };
            match r.flow_dir {
                Some(FlowDir::AtoB) => ab.push(Segment { seq, payload: &r.payload }),
                Some(FlowDir::BtoA) => ba.push(Segment { seq, payload: &r.payload }),
                None => {}
            }
        }

        // If we couldn't collect segments (seq missing), fall back.
        if !ab.is_empty() || !ba.is_empty() {
            return StreamData {
                a_to_b: reassemble(ab),
                b_to_a: reassemble(ba),
            };
        }
    }

    // Fallback: concat in capture order
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
