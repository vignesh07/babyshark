use crate::flow::{FlowIndex, FlowStats};
use crate::pcap::PacketRow;
use crate::stream::build_stream;
use crate::ui_filter::FlowFilter;
use anyhow::Result;
use std::path::{Path, PathBuf};

pub struct ReportOptions {
    pub max_flows: usize,
    pub max_stream_bytes: usize,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            max_flows: 50,
            max_stream_bytes: 16 * 1024,
        }
    }
}

fn truncate_bytes(bytes: &[u8], max: usize) -> (&[u8], bool) {
    if bytes.len() <= max {
        (bytes, false)
    } else {
        (&bytes[..max], true)
    }
}

pub fn write_report_md(
    out_path: &Path,
    pcap_path: &Path,
    rows: &[PacketRow],
    flows: &FlowIndex,
    filter: &FlowFilter,
    bookmarks: &[crate::casefile::FlowBookmark],
    selected_flow: Option<&FlowStats>,
    opts: ReportOptions,
) -> Result<PathBuf> {
    let mut md = String::new();

    md.push_str("# babyshark report\n\n");
    md.push_str(&format!("PCAP: `{}`\n\n", pcap_path.display()));
    md.push_str(&format!("Packets: **{}**\n\n", rows.len()));

    // Filter summary
    md.push_str("## Filter\n\n");
    md.push_str(&format!("- query: `{}`\n", filter.query.trim()));
    md.push_str(&format!(
        "- tcp: {}\n",
        if filter.show_tcp { "on" } else { "off" }
    ));
    md.push_str(&format!(
        "- udp: {}\n\n",
        if filter.show_udp { "on" } else { "off" }
    ));

    // Flows summary
    md.push_str("## Flows (top)\n\n");
    md.push_str("| # | proto | pkts | bytes | endpoints |\n");
    md.push_str("|---:|:-----|-----:|------:|:----------|\n");

    let mut shown = 0usize;
    for (i, f) in flows.flows.iter().enumerate() {
        if !filter.matches(f) {
            continue;
        }
        shown += 1;
        if shown > opts.max_flows {
            break;
        }
        let proto = match f.key.proto {
            crate::pcap::L4Proto::Tcp => "TCP",
            crate::pcap::L4Proto::Udp => "UDP",
            crate::pcap::L4Proto::Other(_) => "L4",
        };
        let endpoints = format!(
            "{}:{} ↔ {}:{}",
            f.key.src, f.key.src_port, f.key.dst, f.key.dst_port
        );
        md.push_str(&format!(
            "| {} | {} | {} | {} | `{}` |\n",
            i + 1,
            proto,
            f.total_packets,
            f.total_bytes,
            endpoints
        ));
    }
    if shown == 0 {
        md.push_str("\n_No flows matched the current filter._\n");
    }
    md.push_str("\n");

    // Bookmarks
    if !bookmarks.is_empty() {
        md.push_str("## Bookmarks\n\n");
        for b in bookmarks {
            md.push_str(&format!("- **{}** — {}\n", b.flow_label, b.note));
        }
        md.push_str("\n");
    }

    // Selected flow
    if let Some(fl) = selected_flow {
        md.push_str("## Selected flow\n\n");
        md.push_str(&format!("- {}\n", fl.label()));
        md.push_str(&format!("- packets: {}\n", fl.total_packets));
        md.push_str(&format!("- bytes: {}\n\n", fl.total_bytes));

        let s = build_stream(rows, fl);

        md.push_str("### Stream (A→B)\n\n```\n");
        let (a, a_trunc) = truncate_bytes(&s.a_to_b, opts.max_stream_bytes);
        md.push_str(&String::from_utf8_lossy(a));
        if a_trunc {
            md.push_str("\n\n[truncated]\n");
        }
        md.push_str("\n```\n\n");

        md.push_str("### Stream (B→A)\n\n```\n");
        let (b, b_trunc) = truncate_bytes(&s.b_to_a, opts.max_stream_bytes);
        md.push_str(&String::from_utf8_lossy(b));
        if b_trunc {
            md.push_str("\n\n[truncated]\n");
        }
        md.push_str("\n```\n\n");
    }

    std::fs::write(out_path, md)?;
    Ok(out_path.to_path_buf())
}
