use crate::domains::{build_domains_summary, DomainsSort};
use crate::explain::explain_flow;
use crate::flow::{FlowIndex, FlowStats};
use crate::pcap::PacketRow;
use crate::summary::build_overview;
use crate::ui_filter::FlowFilter;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::{Path, PathBuf};

const DEFAULT_MODEL: &str = "gpt-5-mini";
const RESPONSES_API_URL: &str = "https://api.openai.com/v1/responses";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotMeta {
    pub capture: String,
    pub filtered_flows: usize,
    pub total_flows: usize,
    pub total_packets: usize,
    pub total_bytes: u64,
    pub duration_ms: i64,
    pub live_capture: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotFilter {
    pub query: String,
    pub show_tcp: bool,
    pub show_udp: bool,
    pub subset: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotProtoMix {
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub other_packets: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotTopDomain {
    pub domain: String,
    pub connections: u64,
    pub bytes: u64,
    pub failures: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotWeirdItem {
    pub title: String,
    pub affected_flows: usize,
    pub why: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotFlow {
    pub label: String,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub health: Option<String>,
    pub direction: Option<String>,
    pub tls_version: Option<String>,
    pub explanation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrafficSnapshot {
    pub meta: SnapshotMeta,
    pub filter: SnapshotFilter,
    pub protocol_mix: SnapshotProtoMix,
    pub top_domains: Vec<SnapshotTopDomain>,
    pub weird_findings: Vec<SnapshotWeirdItem>,
    pub top_flows: Vec<SnapshotFlow>,
    pub selected_flow: Option<SnapshotFlow>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AiSummaryOptions {
    pub model: String,
    pub top_n: usize,
}

impl Default for AiSummaryOptions {
    fn default() -> Self {
        Self {
            model: default_model(),
            top_n: 5,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ResponsesApiResponse {
    output_text: Option<String>,
    output: Option<Vec<ResponsesOutputItem>>,
    error: Option<ResponsesError>,
}

#[derive(Debug, Deserialize)]
struct ResponsesError {
    message: String,
}

#[derive(Debug, Deserialize)]
struct ResponsesOutputItem {
    content: Option<Vec<ResponsesContentItem>>,
}

#[derive(Debug, Deserialize)]
struct ResponsesContentItem {
    #[serde(rename = "type")]
    kind: Option<String>,
    text: Option<String>,
}

pub fn default_model() -> String {
    std::env::var("BABYSHARK_OPENAI_MODEL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_MODEL.to_string())
}

pub fn default_base_url() -> String {
    std::env::var("BABYSHARK_OPENAI_BASE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|s| normalize_base_url(&s))
        .unwrap_or_else(|| RESPONSES_API_URL.to_string())
}

pub fn has_api_key() -> bool {
    std::env::var("OPENAI_API_KEY")
        .ok()
        .is_some_and(|v| !v.trim().is_empty())
}

pub fn api_key_status_label() -> &'static str {
    if has_api_key() {
        "detected"
    } else {
        "missing"
    }
}

pub fn build_snapshot(
    pcap_path: &Path,
    rows: &[PacketRow],
    flows: &FlowIndex,
    filter: &FlowFilter,
    subset_label: Option<&str>,
    selected_flow: Option<&FlowStats>,
    top_n: usize,
) -> TrafficSnapshot {
    let top_n = top_n.max(1).min(10);
    let visible_flow_indices: Vec<usize> = flows
        .flows
        .iter()
        .enumerate()
        .filter(|(_, f)| filter.matches(f))
        .map(|(i, _)| i)
        .collect();
    let visible_flows: Vec<&FlowStats> = visible_flow_indices
        .iter()
        .filter_map(|i| flows.flows.get(*i))
        .collect();

    let overview = build_overview(rows, flows, top_n);
    let weird = crate::weird::build_weird_summary(rows, flows);
    let domains = build_domains_summary(rows, flows, DomainsSort::Connections);

    let duration_ms = match (rows.first(), rows.last()) {
        (Some(first), Some(last)) => (last.ts - first.ts).num_milliseconds().max(0),
        _ => 0,
    };

    let mut notes = Vec::new();
    if rows
        .iter()
        .all(|r| r.tls_sni.is_none() && r.http_host.is_none() && r.dns_qname.is_none())
    {
        notes.push("Very little hostname metadata was visible in this capture.".to_string());
    }
    if rows
        .iter()
        .any(|r| r.proto == Some(crate::pcap::L4Proto::Tcp))
        && rows
            .iter()
            .all(|r| !r.tcp_retransmission && !r.tcp_out_of_order)
    {
        notes.push(
            "No live TCP analysis hints were present; retransmit detection may be limited."
                .to_string(),
        );
    }
    if rows
        .iter()
        .any(|r| r.proto == Some(crate::pcap::L4Proto::Tcp) && r.tls_version.is_none())
    {
        notes.push("Most encrypted flows do not expose payload contents; conclusions rely on metadata and timing.".to_string());
    }

    TrafficSnapshot {
        meta: SnapshotMeta {
            capture: pcap_path.display().to_string(),
            filtered_flows: visible_flows.len(),
            total_flows: flows.flows.len(),
            total_packets: rows.len(),
            total_bytes: overview.total_bytes,
            duration_ms,
            live_capture: pcap_path.to_string_lossy().starts_with("live:"),
        },
        filter: SnapshotFilter {
            query: filter.query.clone(),
            show_tcp: filter.show_tcp,
            show_udp: filter.show_udp,
            subset: subset_label.map(|s| s.to_string()),
        },
        protocol_mix: SnapshotProtoMix {
            tcp_packets: overview.protos.tcp,
            udp_packets: overview.protos.udp,
            other_packets: overview.protos.other,
        },
        top_domains: domains
            .items
            .into_iter()
            .take(top_n)
            .map(|item| SnapshotTopDomain {
                domain: item.domain,
                connections: item.stats.connections,
                bytes: item.stats.bytes,
                failures: item.stats.failures,
            })
            .collect(),
        weird_findings: weird
            .items
            .into_iter()
            .filter(|item| !item.flow_indices.is_empty())
            .take(top_n)
            .map(|item| SnapshotWeirdItem {
                title: item.title,
                affected_flows: item.flow_indices.len(),
                why: item.why,
            })
            .collect(),
        top_flows: visible_flows
            .into_iter()
            .take(top_n)
            .map(|fl| snapshot_flow(rows, fl))
            .collect(),
        selected_flow: selected_flow.map(|fl| snapshot_flow(rows, fl)),
        notes,
    }
}

fn snapshot_flow(rows: &[PacketRow], fl: &FlowStats) -> SnapshotFlow {
    let explanation = explain_flow(rows, fl);
    SnapshotFlow {
        label: fl.label(),
        total_packets: fl.total_packets,
        total_bytes: fl.total_bytes,
        health: fl.analysis.as_ref().map(|a| match a.health {
            crate::flow::HealthBadge::Green => "healthy".to_string(),
            crate::flow::HealthBadge::Yellow => "warning".to_string(),
            crate::flow::HealthBadge::Red => "problem".to_string(),
        }),
        direction: fl.asymmetry_detail_label().map(|s| s.to_string()),
        tls_version: detect_tls_version(rows, fl),
        explanation: Some(explanation.likely),
    }
}

fn detect_tls_version(rows: &[PacketRow], fl: &FlowStats) -> Option<String> {
    let ver = fl
        .packet_indices
        .iter()
        .find_map(|&pi| rows.get(pi).and_then(|r| r.tls_version))?;
    Some(match ver {
        0x0300 => "SSL 3.0".to_string(),
        0x0301 => "TLS 1.0".to_string(),
        0x0302 => "TLS 1.1".to_string(),
        0x0303 => "TLS 1.2".to_string(),
        0x0304 => "TLS 1.3".to_string(),
        _ => format!("0x{ver:04X}"),
    })
}

pub fn write_ai_summary_md(
    out_path: &Path,
    pcap_path: &Path,
    snapshot: &TrafficSnapshot,
    opts: &AiSummaryOptions,
) -> Result<PathBuf> {
    let summary = request_ai_summary(snapshot, opts)?;
    write_ai_summary_md_from_text(out_path, pcap_path, snapshot, &opts.model, &summary)
}

pub fn write_ai_summary_md_from_text(
    out_path: &Path,
    pcap_path: &Path,
    snapshot: &TrafficSnapshot,
    model: &str,
    summary: &str,
) -> Result<PathBuf> {
    let snapshot_json =
        serde_json::to_string_pretty(snapshot).context("serialize traffic snapshot")?;

    let mut md = String::new();
    md.push_str("# babyshark AI summary\n\n");
    md.push_str(&format!("Capture: `{}`\n\n", pcap_path.display()));
    md.push_str(&format!("Model: `{}`\n\n", model));
    md.push_str(summary);
    if !summary.ends_with('\n') {
        md.push('\n');
    }
    md.push_str("\n## Snapshot JSON\n\n```json\n");
    md.push_str(&snapshot_json);
    md.push_str("\n```\n");

    std::fs::write(out_path, md).with_context(|| format!("write {}", out_path.display()))?;
    Ok(out_path.to_path_buf())
}

pub fn request_ai_summary(snapshot: &TrafficSnapshot, opts: &AiSummaryOptions) -> Result<String> {
    let api_key = std::env::var("OPENAI_API_KEY")
        .context("OPENAI_API_KEY is not set; required for AI summary export")?;
    let base_url = default_base_url();
    let snapshot_json =
        serde_json::to_string_pretty(snapshot).context("serialize traffic snapshot")?;

    let instructions = concat!(
        "You are analyzing a redacted network traffic snapshot from babyshark.\n",
        "Write a concise markdown report with these sections in order:\n",
        "## What happened\n",
        "## Strongest evidence\n",
        "## Uncertainty and limitations\n",
        "## Next steps\n",
        "Be explicit when evidence is incomplete.\n",
        "Do not claim decrypted visibility into TLS payloads.\n",
        "Reference the most important domains, flows, and weird findings.\n",
        "Keep the output under 350 words."
    );

    let payload = json!({
        "model": opts.model,
        "reasoning": { "effort": "low" },
        "instructions": instructions,
        "input": format!("Analyze this traffic snapshot JSON and explain what likely happened:\n\n{snapshot_json}")
    });

    let response = reqwest::blocking::Client::new()
        .post(&base_url)
        .bearer_auth(api_key)
        .json(&payload)
        .send()
        .context("request OpenAI Responses API")?;

    let status = response.status();
    let body = response.text().context("read OpenAI response body")?;
    if !status.is_success() {
        return Err(anyhow!("OpenAI API request failed ({status}): {body}"));
    }

    let parsed: ResponsesApiResponse =
        serde_json::from_str(&body).context("parse OpenAI response JSON")?;

    if let Some(err) = parsed.error {
        return Err(anyhow!("OpenAI API error: {}", err.message));
    }

    parsed_output_text(&parsed)
        .ok_or_else(|| anyhow!("OpenAI response did not include text output"))
}

fn parsed_output_text(resp: &ResponsesApiResponse) -> Option<String> {
    if let Some(text) = resp.output_text.as_ref().filter(|s| !s.trim().is_empty()) {
        return Some(text.trim().to_string());
    }

    let mut joined = Vec::new();
    for item in resp.output.as_ref()? {
        for content in item.content.as_ref().into_iter().flatten() {
            if content.kind.as_deref() == Some("output_text") {
                if let Some(text) = content.text.as_ref().filter(|s| !s.trim().is_empty()) {
                    joined.push(text.trim().to_string());
                }
            }
        }
    }

    if joined.is_empty() {
        None
    } else {
        Some(joined.join("\n\n"))
    }
}

fn normalize_base_url(input: &str) -> String {
    let trimmed = input.trim().trim_end_matches('/');
    if trimmed.ends_with("/responses") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/responses")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::FlowIndex;
    use crate::pcap::read_pcap;

    mod fixtures {
        include!("../tests/fixtures/mod.rs");
    }

    #[test]
    fn snapshot_contains_top_level_capture_info() {
        let dir = tempfile::tempdir().unwrap();
        let pcap = dir.path().join("x.pcap");
        {
            let mut f = std::fs::File::create(&pcap).unwrap();
            fixtures::write_two_tcp_packets(&mut f);
        }

        let rows = read_pcap(&pcap).unwrap();
        let mut flows = FlowIndex::build(&rows);
        crate::flow::analyze_flows(&mut flows, &rows);
        let snapshot = build_snapshot(
            &pcap,
            &rows,
            &flows,
            &FlowFilter::default(),
            None,
            flows.flows.first(),
            5,
        );

        assert_eq!(snapshot.meta.total_packets, 2);
        assert_eq!(snapshot.meta.total_flows, 1);
        assert!(!snapshot.top_flows.is_empty());
        assert!(snapshot.selected_flow.is_some());
    }

    #[test]
    fn response_parser_prefers_output_text() {
        let resp: ResponsesApiResponse = serde_json::from_value(json!({
            "output_text": "hello"
        }))
        .unwrap();
        assert_eq!(parsed_output_text(&resp).as_deref(), Some("hello"));
    }

    #[test]
    fn response_parser_falls_back_to_output_items() {
        let resp: ResponsesApiResponse = serde_json::from_value(json!({
            "output": [
                {
                    "content": [
                        { "type": "output_text", "text": "part one" },
                        { "type": "output_text", "text": "part two" }
                    ]
                }
            ]
        }))
        .unwrap();
        assert_eq!(
            parsed_output_text(&resp).as_deref(),
            Some("part one\n\npart two")
        );
    }

    #[test]
    fn has_api_key_checks_non_empty_env_var() {
        let prev = std::env::var("OPENAI_API_KEY").ok();

        unsafe {
            std::env::remove_var("OPENAI_API_KEY");
        }
        assert!(!has_api_key());

        unsafe {
            std::env::set_var("OPENAI_API_KEY", "sk-test");
        }
        assert!(has_api_key());

        match prev {
            Some(v) => unsafe { std::env::set_var("OPENAI_API_KEY", v) },
            None => unsafe { std::env::remove_var("OPENAI_API_KEY") },
        }
    }

    #[test]
    fn normalize_base_url_preserves_default_openai_url() {
        assert_eq!(
            normalize_base_url("https://api.openai.com/v1/responses"),
            RESPONSES_API_URL
        );
    }

    #[test]
    fn default_base_url_appends_responses_when_needed() {
        let prev = std::env::var("BABYSHARK_OPENAI_BASE_URL").ok();
        unsafe {
            std::env::set_var("BABYSHARK_OPENAI_BASE_URL", "https://example.com/v1");
        }
        assert_eq!(default_base_url(), "https://example.com/v1/responses");
        unsafe {
            std::env::set_var(
                "BABYSHARK_OPENAI_BASE_URL",
                "https://example.com/custom/responses/",
            );
        }
        assert_eq!(default_base_url(), "https://example.com/custom/responses");
        match prev {
            Some(v) => unsafe { std::env::set_var("BABYSHARK_OPENAI_BASE_URL", v) },
            None => unsafe { std::env::remove_var("BABYSHARK_OPENAI_BASE_URL") },
        }
    }
}
