use chrono::{DateTime, Utc};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use std::collections::{HashMap, HashSet};

use super::{c_highlight_bg, c_muted, c_text, App, TimelineTab};
use crate::flow::{FlowStats, HealthBadge};
use crate::pcap::{FlowDir, L4Proto, PacketRow};

// ── Phase colors ────────────────────────────────────────────────────────

const C_PHASE_HANDSHAKE: Color = Color::Yellow;
const C_PHASE_TLS: Color = Color::Magenta;
const C_PHASE_DATA: Color = Color::Cyan;
const C_PHASE_CLOSE: Color = Color::Rgb(100, 110, 130);
const C_PHASE_UDP: Color = Color::Green;

// TCP flag masks
const TCP_FLAG_FIN: u16 = 0x01;
const TCP_FLAG_SYN: u16 = 0x02;
const TCP_FLAG_RST: u16 = 0x04;
const TCP_FLAG_ACK: u16 = 0x10;

// ── Phase extraction ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum Phase {
    Handshake, // SYN / SYN-ACK / ACK (3-way)
    Tls,       // first data up to ~5 packets (TLS negotiation heuristic)
    Data,      // bulk data transfer
    Close,     // FIN / RST
}

/// Timestamps marking phase boundaries for a TCP flow.
#[derive(Debug, Clone)]
struct PhaseTimestamps {
    syn_ts: Option<DateTime<Utc>>,
    syn_ack_ts: Option<DateTime<Utc>>,
    first_data_ts: Option<DateTime<Utc>>,
    fin_ts: Option<DateTime<Utc>>,
    has_tls: bool,
}

fn extract_phases(fl: &FlowStats, rows: &[PacketRow]) -> PhaseTimestamps {
    let mut syn_ts: Option<DateTime<Utc>> = None;
    let mut syn_ack_ts: Option<DateTime<Utc>> = None;
    let mut first_data_ts: Option<DateTime<Utc>> = None;
    let mut fin_ts: Option<DateTime<Utc>> = None;
    let mut has_tls = false;

    for &pi in &fl.packet_indices {
        let Some(r) = rows.get(pi) else { continue };
        let flags = r.tcp_flags.unwrap_or(0);

        let is_syn = (flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) == 0;
        let is_syn_ack = (flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) != 0;
        let is_fin = (flags & TCP_FLAG_FIN) != 0;
        let is_rst = (flags & TCP_FLAG_RST) != 0;
        let is_pure_control = is_syn || is_fin || is_rst;

        if is_syn && syn_ts.is_none() {
            syn_ts = Some(r.ts);
        }
        if is_syn_ack && syn_ack_ts.is_none() {
            syn_ack_ts = Some(r.ts);
        }
        if !is_pure_control && !r.payload.is_empty() && first_data_ts.is_none() {
            first_data_ts = Some(r.ts);
        }
        if (is_fin || is_rst) && fin_ts.is_none() {
            fin_ts = Some(r.ts);
        }
        if r.tls_version.is_some() {
            has_tls = true;
        }
    }

    PhaseTimestamps {
        syn_ts,
        syn_ack_ts,
        first_data_ts,
        fin_ts,
        has_tls,
    }
}

/// Determine the phase for a given column position in the bar.
fn col_phase(col_ts: DateTime<Utc>, phases: &PhaseTimestamps, is_tcp: bool) -> Phase {
    if !is_tcp {
        return Phase::Data;
    }

    // Close: at or after FIN/RST
    if let Some(fin) = phases.fin_ts {
        if col_ts >= fin {
            return Phase::Close;
        }
    }

    // Data: after first data (and not close)
    if let Some(first_data) = phases.first_data_ts {
        // If TLS, the early data packets are TLS negotiation
        if phases.has_tls {
            if let Some(syn_ack) = phases.syn_ack_ts {
                // Heuristic: TLS negotiation happens between SYN-ACK and ~first_data + small delta
                // Use first_data as the boundary: everything from syn_ack to first_data is TLS
                if col_ts > syn_ack && col_ts <= first_data {
                    return Phase::Tls;
                }
            }
        }
        if col_ts >= first_data {
            return Phase::Data;
        }
    }

    // TLS: between SYN-ACK and first data (if has_tls)
    if phases.has_tls {
        if let Some(syn_ack) = phases.syn_ack_ts {
            if col_ts > syn_ack {
                return Phase::Tls;
            }
        }
    }

    // Fallback: no payload captured but handshake completed —
    // treat everything after SYN-ACK as Data (not Handshake).
    if let Some(syn_ack) = phases.syn_ack_ts {
        if col_ts > syn_ack {
            return Phase::Data;
        }
    }

    // Handshake: SYN..SYN-ACK..ACK
    Phase::Handshake
}

fn phase_color(phase: Phase) -> Color {
    match phase {
        Phase::Handshake => C_PHASE_HANDSHAKE,
        Phase::Tls => C_PHASE_TLS,
        Phase::Data => C_PHASE_DATA,
        Phase::Close => C_PHASE_CLOSE,
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Map a timestamp to a column index within the bar area.
fn ts_to_col(ts: DateTime<Utc>, start: DateTime<Utc>, end: DateTime<Utc>, cols: usize) -> usize {
    if cols == 0 || start >= end {
        return 0;
    }
    let total_us = (end - start).num_microseconds().unwrap_or(1).max(1);
    let offset_us = (ts - start).num_microseconds().unwrap_or(0).max(0);
    let col = (offset_us as u128 * cols as u128 / total_us as u128) as usize;
    col.min(cols.saturating_sub(1))
}

/// Map a column back to a timestamp (for phase coloring).
fn col_to_ts(col: usize, start: DateTime<Utc>, end: DateTime<Utc>, cols: usize) -> DateTime<Utc> {
    if cols <= 1 {
        return start;
    }
    let total_us = (end - start).num_microseconds().unwrap_or(0);
    let frac = col as f64 / (cols - 1).max(1) as f64;
    start + chrono::Duration::microseconds((frac * total_us as f64) as i64)
}

/// Returns (start_ts, end_ts) using min/max packet timestamps in the capture.
/// Returns None if timestamps are missing or capture duration is zero.
pub(super) fn capture_time_range(app: &App) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let mut min_ts: Option<DateTime<Utc>> = None;
    let mut max_ts: Option<DateTime<Utc>> = None;

    for row in &app.rows {
        min_ts = Some(match min_ts {
            Some(ts) => ts.min(row.ts),
            None => row.ts,
        });
        max_ts = Some(match max_ts {
            Some(ts) => ts.max(row.ts),
            None => row.ts,
        });
    }

    let first = min_ts?;
    let last = max_ts?;
    if first == last {
        return None;
    }
    Some((first, last))
}

/// Build a time axis header line with evenly-spaced timestamp labels.
pub(super) fn build_time_axis(
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    bar_width: usize,
    label_width: usize,
) -> Line<'static> {
    let mut spans: Vec<Span> = Vec::new();

    // Left label area (empty for the axis)
    spans.push(Span::styled(
        " ".repeat(label_width + 2), // +2 for badge column
        Style::default(),
    ));

    if bar_width < 10 {
        spans.push(Span::styled(
            format!("{}", start.format("%H:%M:%S")),
            Style::default().fg(c_muted()),
        ));
        return Line::from(spans);
    }

    // Place ~5 evenly-spaced labels
    let n_labels = 5usize.min(bar_width / 8).max(2);
    let mut axis_buf = vec![b' '; bar_width];

    for i in 0..n_labels {
        let col = if n_labels == 1 {
            0
        } else {
            i * (bar_width - 1) / (n_labels - 1)
        };
        let frac = if n_labels == 1 {
            0.0
        } else {
            i as f64 / (n_labels - 1) as f64
        };
        let total_us = (end - start).num_microseconds().unwrap_or(0) as f64;
        let ts = start + chrono::Duration::microseconds((frac * total_us) as i64);
        let label = ts.format("%H:%M:%S").to_string();
        let label_bytes = label.as_bytes();
        let start_col = col.min(bar_width.saturating_sub(label_bytes.len()));
        for (j, &b) in label_bytes.iter().enumerate() {
            if start_col + j < bar_width {
                axis_buf[start_col + j] = b;
            }
        }
    }

    spans.push(Span::styled(
        String::from_utf8_lossy(&axis_buf).to_string(),
        Style::default().fg(c_muted()),
    ));

    Line::from(spans)
}

/// Build a legend line explaining Gantt phase colors.
pub(super) fn build_gantt_legend(label_width: usize) -> Line<'static> {
    let mut spans: Vec<Span> = Vec::new();
    spans.push(Span::styled(
        " ".repeat(label_width + 2),
        Style::default(),
    ));
    spans.push(Span::styled("█", Style::default().fg(C_PHASE_HANDSHAKE)));
    spans.push(Span::styled(" handshake  ", Style::default().fg(c_muted())));
    spans.push(Span::styled("█", Style::default().fg(C_PHASE_TLS)));
    spans.push(Span::styled(" TLS  ", Style::default().fg(c_muted())));
    spans.push(Span::styled("█", Style::default().fg(C_PHASE_DATA)));
    spans.push(Span::styled(" data  ", Style::default().fg(c_muted())));
    spans.push(Span::styled("█", Style::default().fg(C_PHASE_CLOSE)));
    spans.push(Span::styled(" close  ", Style::default().fg(c_muted())));
    spans.push(Span::styled("█", Style::default().fg(C_PHASE_UDP)));
    spans.push(Span::styled(" UDP", Style::default().fg(c_muted())));
    Line::from(spans)
}

/// Build a legend line explaining Scatter dot colors.
pub(super) fn build_scatter_legend(label_width: usize) -> Line<'static> {
    let mut spans: Vec<Span> = Vec::new();
    spans.push(Span::styled(
        " ".repeat(label_width + 2),
        Style::default(),
    ));
    spans.push(Span::styled("●", Style::default().fg(Color::Cyan)));
    spans.push(Span::styled(" you→server  ", Style::default().fg(c_muted())));
    spans.push(Span::styled("●", Style::default().fg(Color::Magenta)));
    spans.push(Span::styled(" server→you  ", Style::default().fg(c_muted())));
    spans.push(Span::styled("●", Style::default().fg(Color::Red)));
    spans.push(Span::styled(" retransmit  ", Style::default().fg(c_muted())));
    spans.push(Span::styled("█", Style::default().fg(Color::White)));
    spans.push(Span::styled(" burst", Style::default().fg(c_muted())));
    Line::from(spans)
}

fn health_color(fl: &FlowStats) -> Color {
    fl.analysis
        .as_ref()
        .map(|a| match a.health {
            HealthBadge::Green => Color::Green,
            HealthBadge::Yellow => Color::Yellow,
            HealthBadge::Red => Color::Red,
        })
        .unwrap_or(Color::Green)
}

fn health_badge_span(fl: &FlowStats) -> Span<'static> {
    let color = health_color(fl);
    Span::styled("● ", Style::default().fg(color))
}

/// Build a human-readable label using hostname when available.
fn friendly_label(
    fl: &FlowStats,
    ip_host: &HashMap<std::net::IpAddr, String>,
    width: usize,
) -> String {
    let proto = match fl.key.proto {
        L4Proto::Tcp => "TCP",
        L4Proto::Udp => "UDP",
        L4Proto::Other(_) => "L4",
    };

    // Try to find a hostname for the dst (server) side, or src
    let host = ip_host
        .get(&fl.key.dst)
        .or_else(|| ip_host.get(&fl.key.src));

    let full = if let Some(h) = host {
        // Prefer: "google.com (HTTPS)" over raw IPs
        let port_hint = match fl.key.dst_port {
            443 => "HTTPS",
            80 => "HTTP",
            53 => "DNS",
            _ => "",
        };
        if port_hint.is_empty() {
            format!("{proto} {h}:{}", fl.key.dst_port)
        } else {
            format!("{h} ({port_hint})")
        }
    } else {
        format!(
            "{proto} {}:{}",
            fl.key.dst, fl.key.dst_port
        )
    };

    let full_chars = full.chars().count();
    if full_chars <= width {
        format!("{:<width$}", full, width = width)
    } else if width <= 1 {
        if width == 0 { String::new() } else { "…".to_string() }
    } else {
        let mut s: String = full.chars().take(width - 1).collect();
        s.push('…');
        s
    }
}

// ── Gantt row (phase-colored) ───────────────────────────────────────────

/// Build a single Gantt row: label + badge + phase-colored horizontal bar.
pub(super) fn build_gantt_row(
    fl: &FlowStats,
    rows: &[PacketRow],
    ip_host: &HashMap<std::net::IpAddr, String>,
    capture_start: DateTime<Utc>,
    capture_end: DateTime<Utc>,
    bar_width: usize,
    label_width: usize,
    selected: bool,
) -> Line<'static> {
    let mut spans: Vec<Span> = Vec::new();

    let base_style = if selected {
        Style::default()
            .bg(c_highlight_bg())
            .fg(c_text())
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(c_text())
    };

    spans.push(Span::styled(friendly_label(fl, ip_host, label_width), base_style));
    spans.push(health_badge_span(fl));

    if bar_width < 2 {
        return Line::from(spans);
    }

    let (flow_start, flow_end) = match (fl.first_ts, fl.last_ts) {
        (Some(s), Some(e)) => (s, e),
        _ => return Line::from(spans),
    };

    let start_col = ts_to_col(flow_start, capture_start, capture_end, bar_width);
    let end_col = ts_to_col(flow_end, capture_start, capture_end, bar_width);

    let is_tcp = fl.key.proto == L4Proto::Tcp;

    if is_tcp {
        let phases = extract_phases(fl, rows);

        // Build bar with per-column phase coloring
        let mut current_color: Option<Color> = None;
        let mut current_chars = String::new();

        for c in 0..bar_width {
            if c >= start_col && c <= end_col {
                let col_ts = col_to_ts(c, capture_start, capture_end, bar_width);
                let phase = col_phase(col_ts, &phases, true);
                let color = phase_color(phase);

                if current_color == Some(color) {
                    current_chars.push('█');
                } else {
                    if !current_chars.is_empty() {
                        spans.push(Span::styled(
                            std::mem::take(&mut current_chars),
                            Style::default().fg(current_color.unwrap_or(c_muted())),
                        ));
                    }
                    current_color = Some(color);
                    current_chars.push('█');
                }
            } else {
                let space_color = c_muted();
                if current_color == Some(space_color) {
                    current_chars.push(' ');
                } else {
                    if !current_chars.is_empty() {
                        spans.push(Span::styled(
                            std::mem::take(&mut current_chars),
                            Style::default().fg(current_color.unwrap_or(c_muted())),
                        ));
                    }
                    current_color = Some(space_color);
                    current_chars.push(' ');
                }
            }
        }
        if !current_chars.is_empty() {
            spans.push(Span::styled(
                current_chars,
                Style::default().fg(current_color.unwrap_or(c_muted())),
            ));
        }
    } else {
        // UDP/other: single color bar
        let mut bar = String::with_capacity(bar_width);
        for c in 0..bar_width {
            if c >= start_col && c <= end_col {
                bar.push('█');
            } else {
                bar.push(' ');
            }
        }
        spans.push(Span::styled(bar, Style::default().fg(C_PHASE_UDP)));
    }

    Line::from(spans)
}

// ── Scatter row ─────────────────────────────────────────────────────────

/// Build a single Scatter row: label + per-packet dots.
pub(super) fn build_scatter_row(
    fl: &FlowStats,
    rows: &[PacketRow],
    ip_host: &HashMap<std::net::IpAddr, String>,
    capture_start: DateTime<Utc>,
    capture_end: DateTime<Utc>,
    bar_width: usize,
    label_width: usize,
    selected: bool,
) -> Line<'static> {
    let mut spans: Vec<Span> = Vec::new();

    let base_style = if selected {
        Style::default()
            .bg(c_highlight_bg())
            .fg(c_text())
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(c_text())
    };

    spans.push(Span::styled(friendly_label(fl, ip_host, label_width), base_style));
    spans.push(health_badge_span(fl));

    if bar_width < 2 {
        return Line::from(spans);
    }

    // For each column, track what kind of packet(s) land there.
    // 0 = empty, 1 = AtoB, 2 = BtoA, 3 = retransmit/OOO, 4 = collision (multiple)
    let mut grid: Vec<u8> = vec![0; bar_width];
    let mut counts: Vec<usize> = vec![0; bar_width];

    for &pi in &fl.packet_indices {
        let Some(r) = rows.get(pi) else { continue };
        let col = ts_to_col(r.ts, capture_start, capture_end, bar_width);
        counts[col] = counts[col].saturating_add(1);

        if r.tcp_retransmission || r.tcp_out_of_order {
            grid[col] = 3; // retransmit takes priority color
        } else if grid[col] == 0 {
            grid[col] = match r.flow_dir {
                Some(FlowDir::AtoB) => 1,
                Some(FlowDir::BtoA) => 2,
                None => 1,
            };
        } else if grid[col] != 3 {
            let new_kind = match r.flow_dir {
                Some(FlowDir::AtoB) => 1,
                Some(FlowDir::BtoA) => 2,
                None => 1,
            };
            if grid[col] != new_kind {
                grid[col] = 4; // collision: mixed directions
            }
        }
    }

    // Build the dot string column by column, batching spans by color.
    let mut current_color: Option<Color> = None;
    let mut current_chars = String::new();

    for col in 0..bar_width {
        let (ch, color) = match grid[col] {
            0 => (' ', c_muted()),
            1 => {
                if counts[col] > 1 {
                    ('█', Color::Cyan)
                } else {
                    ('●', Color::Cyan)
                }
            }
            2 => {
                if counts[col] > 1 {
                    ('█', Color::Magenta)
                } else {
                    ('●', Color::Magenta)
                }
            }
            3 => ('●', Color::Red),
            4 => ('█', Color::White),
            _ => (' ', c_muted()),
        };

        if current_color == Some(color) {
            current_chars.push(ch);
        } else {
            if !current_chars.is_empty() {
                spans.push(Span::styled(
                    std::mem::take(&mut current_chars),
                    Style::default().fg(current_color.unwrap_or(c_muted())),
                ));
            }
            current_color = Some(color);
            current_chars.push(ch);
        }
    }

    if !current_chars.is_empty() {
        spans.push(Span::styled(
            current_chars,
            Style::default().fg(current_color.unwrap_or(c_muted())),
        ));
    }

    Line::from(spans)
}

// ── Narrative (plain-English timeline story) ────────────────────────────

/// Build a plain-English narrative for a flow's timeline in the details panel.
pub(super) fn build_narrative(fl: &FlowStats, rows: &[PacketRow], ip_host: &HashMap<std::net::IpAddr, String>) -> Vec<Line<'static>> {
    let mut out: Vec<Line> = Vec::new();

    let host = ip_host
        .get(&fl.key.dst)
        .or_else(|| ip_host.get(&fl.key.src))
        .cloned()
        .unwrap_or_else(|| fl.key.dst.to_string());

    let is_tcp = fl.key.proto == L4Proto::Tcp;

    // Title
    out.push(Line::from(Span::styled(
        "What happened",
        Style::default().fg(c_text()).add_modifier(Modifier::BOLD),
    )));
    out.push(Line::from(Span::raw("")));

    if is_tcp {
        let phases = extract_phases(fl, rows);

        // Build the story
        let mut steps: Vec<String> = Vec::new();

        if phases.syn_ts.is_some() && phases.syn_ack_ts.is_some() {
            let rtt = fl.analysis.as_ref()
                .and_then(|a| a.tcp_timing.as_ref())
                .and_then(|t| t.handshake_rtt_us);
            if let Some(us) = rtt {
                steps.push(format!("Connected to {host} (TCP handshake took {:.1}ms)", us as f64 / 1000.0));
            } else {
                steps.push(format!("Connected to {host} (TCP handshake completed)"));
            }
        } else if phases.syn_ts.is_some() {
            steps.push(format!("Tried to connect to {host} (handshake incomplete)"));
        }

        if phases.has_tls {
            let ver = fl.packet_indices.iter().find_map(|&pi| {
                rows.get(pi).and_then(|r| r.tls_version)
            });
            let ver_str = match ver {
                Some(0x0304) => "TLS 1.3",
                Some(0x0303) => "TLS 1.2",
                Some(0x0302) => "TLS 1.1 (deprecated!)",
                Some(0x0301) => "TLS 1.0 (deprecated!)",
                Some(_) => "TLS",
                None => "TLS",
            };
            steps.push(format!("Negotiated encryption ({ver_str})"));
        }

        if phases.first_data_ts.is_some() {
            let kb = fl.total_bytes as f64 / 1024.0;
            let duration = fl.analysis.as_ref()
                .and_then(|a| a.tcp_timing.as_ref())
                .and_then(|t| t.data_transfer_us);
            if let Some(us) = duration {
                steps.push(format!("Transferred {kb:.1}KB in {:.0}ms ({} packets)",
                    us as f64 / 1000.0, fl.total_packets));
            } else {
                steps.push(format!("Transferred {kb:.1}KB ({} packets)", fl.total_packets));
            }
        }

        if let Some(direction) = fl.asymmetry_detail_label() {
            match direction {
                "download-heavy" => {
                    steps.push("Mostly downloading (server sent more data)".to_string());
                }
                "upload-heavy" => {
                    steps.push("Mostly uploading (you sent more data)".to_string());
                }
                "balanced" => {}
                other => {
                    steps.push(format!("Direction is skewed ({other})"));
                }
            }
        }

        if phases.fin_ts.is_some() {
            let had_rst = fl.packet_indices.iter().any(|&pi| {
                rows.get(pi)
                    .and_then(|r| r.tcp_flags)
                    .map(|f| (f & TCP_FLAG_RST) != 0)
                    .unwrap_or(false)
            });
            if had_rst {
                steps.push("Connection was aborted (RST)".to_string());
            } else {
                steps.push("Connection closed cleanly (FIN)".to_string());
            }
        }

        // Health summary
        if let Some(a) = fl.analysis.as_ref() {
            match a.health {
                HealthBadge::Green => {}
                HealthBadge::Yellow => {
                    steps.push("Warning: retransmissions detected (possible packet loss)".to_string());
                }
                HealthBadge::Red => {
                    steps.push("Problem: connection failed or was reset".to_string());
                }
            }
        }

        if steps.is_empty() {
            out.push(Line::from(Span::styled(
                format!("TCP connection to {host}"),
                Style::default().fg(c_muted()),
            )));
        } else {
            for (i, step) in steps.iter().enumerate() {
                out.push(Line::from(vec![
                    Span::styled(format!("{}. ", i + 1), Style::default().fg(c_muted())),
                    Span::styled(step.clone(), Style::default().fg(c_text())),
                ]));
            }
        }
    } else {
        // UDP
        let kb = fl.total_bytes as f64 / 1024.0;
        out.push(Line::from(Span::styled(
            format!("UDP traffic to {host} — {kb:.1}KB across {} packets", fl.total_packets),
            Style::default().fg(c_text()),
        )));
        if fl.key.dst_port == 443 {
            out.push(Line::from(Span::styled(
                "Likely QUIC/HTTP3 (UDP port 443)",
                Style::default().fg(c_muted()),
            )));
        } else if fl.key.dst_port == 53 {
            out.push(Line::from(Span::styled(
                "DNS queries/responses",
                Style::default().fg(c_muted()),
            )));
        }
    }

    out
}

// ── Pattern detection ───────────────────────────────────────────────────

fn normalize_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn host_matches_qname(host: &str, qname: &str) -> bool {
    let host = normalize_name(host);
    let qname = normalize_name(qname);
    if host.is_empty() || qname.is_empty() {
        return false;
    }
    host == qname || host.ends_with(&format!(".{qname}")) || qname.ends_with(&format!(".{host}"))
}

fn dns_queries_for_flow(fl: &FlowStats, rows: &[PacketRow]) -> Vec<String> {
    let mut names = Vec::new();
    for &pi in &fl.packet_indices {
        let Some(r) = rows.get(pi) else { continue };
        let Some(qname) = &r.dns_qname else { continue };
        let q = normalize_name(qname);
        if !q.is_empty() {
            names.push(q);
        }
    }
    names.sort();
    names.dedup();
    names
}

/// Detect interesting patterns across all visible flows and return callout lines.
pub(super) fn detect_patterns(
    app: &App,
    sorted_indices: &[usize],
    ip_host: &HashMap<std::net::IpAddr, String>,
) -> Vec<Line<'static>> {
    let mut out: Vec<Line> = Vec::new();

    if sorted_indices.len() < 2 {
        return out;
    }

    // Pattern 1: Simultaneous opens (multiple flows starting within 100ms)
    let mut burst_count = 0usize;
    let mut burst_ts: Option<DateTime<Utc>> = None;

    for window in sorted_indices.windows(2) {
        let fa = app.flows.flows.get(window[0]).and_then(|f| f.first_ts);
        let fb = app.flows.flows.get(window[1]).and_then(|f| f.first_ts);
        if let (Some(a), Some(b)) = (fa, fb) {
            let delta_ms = (b - a).num_milliseconds().abs();
            if delta_ms <= 100 {
                if burst_ts.is_none() {
                    burst_ts = Some(a);
                    burst_count = 2;
                } else {
                    burst_count += 1;
                }
            } else if burst_count >= 3 {
                break;
            } else {
                burst_ts = None;
                burst_count = 0;
            }
        }
    }

    if burst_count >= 3 {
        out.push(Line::from(vec![
            Span::styled("Pattern: ", Style::default().fg(Color::Rgb(255, 215, 0)).add_modifier(Modifier::BOLD)),
            Span::styled(
                format!("{burst_count} connections opened simultaneously — likely a page load or app startup"),
                Style::default().fg(c_text()),
            ),
        ]));
    }

    // Pattern 2: DNS lookup followed by encrypted connection to the same host.
    let dns_flows: Vec<(usize, DateTime<Utc>, Vec<String>)> = sorted_indices
        .iter()
        .filter_map(|&i| {
            let fl = app.flows.flows.get(i)?;
            if fl.key.proto != L4Proto::Udp || fl.key.dst_port != 53 {
                return None;
            }
            let ts = fl.first_ts?;
            let qnames = dns_queries_for_flow(fl, &app.rows);
            if qnames.is_empty() {
                return None;
            }
            Some((i, ts, qnames))
        })
        .collect();

    let mut matched_dns: HashSet<usize> = HashSet::new();
    let mut matched_tls = 0usize;
    let mut total_tls = 0usize;
    const DNS_TLS_WINDOW_MS: i64 = 30_000;

    for &i in sorted_indices {
        let Some(fl) = app.flows.flows.get(i) else { continue };
        if fl.key.proto != L4Proto::Tcp || fl.key.dst_port != 443 {
            continue;
        }
        total_tls += 1;
        let Some(tls_ts) = fl.first_ts else { continue };
        let Some(host) = ip_host.get(&fl.key.dst).or_else(|| ip_host.get(&fl.key.src)) else {
            continue;
        };

        for (dns_flow_idx, dns_ts, qnames) in &dns_flows {
            if *dns_ts > tls_ts {
                continue;
            }
            let delta_ms = (tls_ts - *dns_ts).num_milliseconds();
            if delta_ms > DNS_TLS_WINDOW_MS {
                continue;
            }
            if qnames.iter().any(|q| host_matches_qname(host, q)) {
                matched_tls += 1;
                matched_dns.insert(*dns_flow_idx);
                break;
            }
        }
    }

    if matched_tls > 0 {
        out.push(Line::from(vec![
            Span::styled("Pattern: ", Style::default().fg(Color::Rgb(255, 215, 0)).add_modifier(Modifier::BOLD)),
            Span::styled(
                format!(
                    "{} DNS lookups preceded {} encrypted connections to matching hosts",
                    matched_dns.len(),
                    matched_tls
                ),
                Style::default().fg(c_text()),
            ),
        ]));
    } else {
        let dns_count = dns_flows.len();
        if dns_count > 0 && total_tls > 0 {
            out.push(Line::from(vec![
                Span::styled("Pattern: ", Style::default().fg(Color::Rgb(255, 215, 0)).add_modifier(Modifier::BOLD)),
                Span::styled(
                    format!(
                        "{dns_count} DNS lookups and {total_tls} encrypted connections are present",
                    ),
                    Style::default().fg(c_text()),
                ),
            ]));
        }
    }

    // Pattern 3: Retransmissions visible
    let retrans_flows: Vec<usize> = sorted_indices.iter().filter(|&&i| {
        app.flows.flows.get(i).map(|f| {
            f.analysis.as_ref().map(|a| a.health == HealthBadge::Yellow).unwrap_or(false)
        }).unwrap_or(false)
    }).copied().collect();

    if !retrans_flows.is_empty() {
        out.push(Line::from(vec![
            Span::styled("Pattern: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(
                format!("{} flows have retransmissions (yellow dots in Scatter) — possible network congestion", retrans_flows.len()),
                Style::default().fg(c_text()),
            ),
        ]));
    }

    out
}

// ── Main builder ────────────────────────────────────────────────────────

/// Build all timeline items: returns (header_lines, flow_rows).
/// Flows are sorted by first_ts for a coherent timeline.
pub(super) fn build_timeline_items(
    app: &App,
    tab: TimelineTab,
    bar_width: usize,
    label_width: usize,
    selected_row: usize,
    ip_host: &HashMap<std::net::IpAddr, String>,
) -> (Vec<Line<'static>>, Vec<Line<'static>>) {
    let Some((capture_start, capture_end)) = capture_time_range(app) else {
        return (
            vec![Line::from(Span::styled(
                "Not enough data for timeline",
                Style::default().fg(c_muted()),
            ))],
            Vec::new(),
        );
    };

    let axis = build_time_axis(capture_start, capture_end, bar_width, label_width);
    let legend = match tab {
        TimelineTab::Gantt => build_gantt_legend(label_width),
        TimelineTab::Scatter => build_scatter_legend(label_width),
    };

    // Sort visible flows by first_ts
    let sorted_indices = timeline_sorted_indices(app);

    let rows: Vec<Line> = sorted_indices
        .iter()
        .enumerate()
        .map(|(i, &flow_idx)| {
            let fl = &app.flows.flows[flow_idx];
            let is_selected = i == selected_row;
            match tab {
                TimelineTab::Gantt => {
                    build_gantt_row(fl, &app.rows, &ip_host, capture_start, capture_end, bar_width, label_width, is_selected)
                }
                TimelineTab::Scatter => {
                    build_scatter_row(fl, &app.rows, &ip_host, capture_start, capture_end, bar_width, label_width, is_selected)
                }
            }
        })
        .collect();

    // Pattern callouts
    let patterns = detect_patterns(app, &sorted_indices, ip_host);

    let mut headers = vec![legend, axis];
    headers.extend(patterns);

    (headers, rows)
}

/// Return the sorted flow indices for Timeline view (sorted by first_ts).
/// This is needed to map timeline_selected_row back to the actual flow index.
pub(super) fn timeline_sorted_indices(app: &App) -> Vec<usize> {
    let mut sorted: Vec<usize> = app.visible_flow_indices.clone();
    sorted.sort_by(|&a, &b| {
        let fa = app.flows.flows.get(a).and_then(|f| f.first_ts);
        let fb = app.flows.flows.get(b).and_then(|f| f.first_ts);
        fa.cmp(&fb)
    });
    sorted
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn mk_packet_row(index: usize, ts_ms: i64) -> PacketRow {
        PacketRow {
            index,
            ts: Utc.timestamp_millis_opt(ts_ms).unwrap(),
            len: 60,
            src: Some("10.0.0.1".parse().unwrap()),
            dst: Some("10.0.0.2".parse().unwrap()),
            proto: Some(L4Proto::Tcp),
            src_port: Some(1234),
            dst_port: Some(80),
            summary: String::new(),
            flow: None,
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
        }
    }

    #[test]
    fn ts_to_col_boundaries() {
        let start = Utc.timestamp_millis_opt(0).unwrap();
        let end = Utc.timestamp_millis_opt(1000).unwrap();

        assert_eq!(ts_to_col(start, start, end, 10), 0);
        assert_eq!(ts_to_col(end, start, end, 10), 9);
        let mid = Utc.timestamp_millis_opt(500).unwrap();
        assert_eq!(ts_to_col(mid, start, end, 10), 5);
    }

    #[test]
    fn ts_to_col_zero_cols() {
        let start = Utc.timestamp_millis_opt(0).unwrap();
        let end = Utc.timestamp_millis_opt(1000).unwrap();
        assert_eq!(ts_to_col(start, start, end, 0), 0);
    }

    #[test]
    fn ts_to_col_same_start_end() {
        let t = Utc.timestamp_millis_opt(100).unwrap();
        assert_eq!(ts_to_col(t, t, t, 10), 0);
    }

    #[test]
    fn capture_time_range_returns_none_for_empty() {
        let app = App::new("/tmp/t.pcap", Vec::new(), crate::flow::FlowIndex::default());
        assert!(capture_time_range(&app).is_none());
    }

    #[test]
    fn capture_time_range_uses_min_max_for_out_of_order_rows() {
        let rows = vec![
            mk_packet_row(0, 500),
            mk_packet_row(1, 100),
            mk_packet_row(2, 300),
        ];
        let app = App::new("/tmp/t.pcap", rows, crate::flow::FlowIndex::default());
        let (start, end) = capture_time_range(&app).expect("capture range should exist");
        assert_eq!(start, Utc.timestamp_millis_opt(100).unwrap());
        assert_eq!(end, Utc.timestamp_millis_opt(500).unwrap());
    }

    #[test]
    fn phase_coloring_for_tcp_handshake() {
        let phases = PhaseTimestamps {
            syn_ts: Some(Utc.timestamp_millis_opt(0).unwrap()),
            syn_ack_ts: Some(Utc.timestamp_millis_opt(50).unwrap()),
            first_data_ts: Some(Utc.timestamp_millis_opt(100).unwrap()),

            fin_ts: Some(Utc.timestamp_millis_opt(600).unwrap()),
            has_tls: false,
        };

        // Before SYN-ACK = handshake
        assert_eq!(col_phase(Utc.timestamp_millis_opt(25).unwrap(), &phases, true), Phase::Handshake);
        // After first_data = data
        assert_eq!(col_phase(Utc.timestamp_millis_opt(200).unwrap(), &phases, true), Phase::Data);
        // At FIN = close
        assert_eq!(col_phase(Utc.timestamp_millis_opt(600).unwrap(), &phases, true), Phase::Close);
    }

    #[test]
    fn phase_coloring_with_tls() {
        let phases = PhaseTimestamps {
            syn_ts: Some(Utc.timestamp_millis_opt(0).unwrap()),
            syn_ack_ts: Some(Utc.timestamp_millis_opt(50).unwrap()),
            first_data_ts: Some(Utc.timestamp_millis_opt(200).unwrap()),

            fin_ts: None,
            has_tls: true,
        };

        // Between SYN-ACK and first_data = TLS
        assert_eq!(col_phase(Utc.timestamp_millis_opt(100).unwrap(), &phases, true), Phase::Tls);
        // After first_data = data
        assert_eq!(col_phase(Utc.timestamp_millis_opt(300).unwrap(), &phases, true), Phase::Data);
    }

    #[test]
    fn phase_coloring_no_payload_falls_back_to_data() {
        // Simulates a capture where payload bytes aren't stored (snap length).
        // first_data_ts is None, but handshake completed — post-SYN-ACK should be Data.
        let phases = PhaseTimestamps {
            syn_ts: Some(Utc.timestamp_millis_opt(0).unwrap()),
            syn_ack_ts: Some(Utc.timestamp_millis_opt(50).unwrap()),
            first_data_ts: None,
            fin_ts: Some(Utc.timestamp_millis_opt(600).unwrap()),
            has_tls: false,
        };

        // Before SYN-ACK = handshake
        assert_eq!(col_phase(Utc.timestamp_millis_opt(25).unwrap(), &phases, true), Phase::Handshake);
        // At SYN-ACK = still handshake
        assert_eq!(col_phase(Utc.timestamp_millis_opt(50).unwrap(), &phases, true), Phase::Handshake);
        // After SYN-ACK = data (NOT handshake)
        assert_eq!(col_phase(Utc.timestamp_millis_opt(100).unwrap(), &phases, true), Phase::Data);
        assert_eq!(col_phase(Utc.timestamp_millis_opt(400).unwrap(), &phases, true), Phase::Data);
        // At FIN = close
        assert_eq!(col_phase(Utc.timestamp_millis_opt(600).unwrap(), &phases, true), Phase::Close);
    }

    #[test]
    fn friendly_label_uses_hostname() {
        let fl = crate::flow::FlowStats {
            key: crate::pcap::FlowKey {
                src: "10.0.0.1".parse().unwrap(),
                dst: "93.184.216.34".parse().unwrap(),
                src_port: 50000,
                dst_port: 443,
                proto: L4Proto::Tcp,
            },
            total_packets: 1,
            total_bytes: 50,
            a_to_b: crate::flow::DirStats::default(),
            b_to_a: crate::flow::DirStats::default(),
            packet_indices: vec![],
            analysis: None,
            first_ts: None,
            last_ts: None,
        };

        let mut ip_host = HashMap::new();
        ip_host.insert("93.184.216.34".parse().unwrap(), "example.com".to_string());

        let label = friendly_label(&fl, &ip_host, 25);
        assert!(label.contains("example.com"), "Label should contain hostname, got: {label}");
        assert!(label.contains("HTTPS"), "Label should show HTTPS for port 443, got: {label}");
    }

    #[test]
    fn friendly_label_falls_back_to_ip() {
        let fl = crate::flow::FlowStats {
            key: crate::pcap::FlowKey {
                src: "10.0.0.1".parse().unwrap(),
                dst: "1.2.3.4".parse().unwrap(),
                src_port: 50000,
                dst_port: 8080,
                proto: L4Proto::Tcp,
            },
            total_packets: 1,
            total_bytes: 50,
            a_to_b: crate::flow::DirStats::default(),
            b_to_a: crate::flow::DirStats::default(),
            packet_indices: vec![],
            analysis: None,
            first_ts: None,
            last_ts: None,
        };

        let ip_host = HashMap::new();
        let label = friendly_label(&fl, &ip_host, 25);
        assert!(label.contains("1.2.3.4"), "Label should contain IP when no hostname, got: {label}");
    }

    #[test]
    fn gantt_legend_contains_all_phases() {
        let line = build_gantt_legend(20);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("handshake"), "Legend missing 'handshake'");
        assert!(text.contains("TLS"), "Legend missing 'TLS'");
        assert!(text.contains("data"), "Legend missing 'data'");
        assert!(text.contains("close"), "Legend missing 'close'");
        assert!(text.contains("UDP"), "Legend missing 'UDP'");
    }

    #[test]
    fn scatter_legend_contains_directions() {
        let line = build_scatter_legend(20);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("server"), "Legend missing direction labels");
        assert!(text.contains("retransmit"), "Legend missing 'retransmit'");
    }

    #[test]
    fn build_gantt_row_phase_colored() {
        use crate::flow::{DirStats, FlowStats};
        use crate::pcap::FlowKey;

        let start = Utc.timestamp_millis_opt(0).unwrap();
        let end = Utc.timestamp_millis_opt(1000).unwrap();

        let rows = vec![
            {
                let mut r = mk_packet_row(0, 0);
                r.tcp_flags = Some(TCP_FLAG_SYN);
                r
            },
            {
                let mut r = mk_packet_row(1, 50);
                r.tcp_flags = Some(TCP_FLAG_SYN | TCP_FLAG_ACK);
                r
            },
            {
                let mut r = mk_packet_row(2, 100);
                r.tcp_flags = Some(TCP_FLAG_ACK);
                r.payload = vec![0u8; 100];
                r
            },
        ];

        let fl = FlowStats {
            key: FlowKey {
                src: "10.0.0.1".parse().unwrap(),
                dst: "10.0.0.2".parse().unwrap(),
                src_port: 1234,
                dst_port: 80,
                proto: L4Proto::Tcp,
            },
            total_packets: 3,
            total_bytes: 180,
            a_to_b: DirStats { packets: 3, bytes: 180 },
            b_to_a: DirStats::default(),
            packet_indices: vec![0, 1, 2],
            analysis: None,
            first_ts: Some(Utc.timestamp_millis_opt(0).unwrap()),
            last_ts: Some(Utc.timestamp_millis_opt(100).unwrap()),
        };

        let ip_host = HashMap::new();
        let line = build_gantt_row(&fl, &rows, &ip_host, start, end, 20, 18, false);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        let bar_count = text.chars().filter(|&c| c == '█').count();
        assert!(bar_count > 0, "Gantt row should have bar characters");
    }

    #[test]
    fn narrow_bar_width_does_not_panic() {
        use crate::flow::{DirStats, FlowStats};
        use crate::pcap::FlowKey;

        let start = Utc.timestamp_millis_opt(0).unwrap();
        let end = Utc.timestamp_millis_opt(1000).unwrap();

        let fl = FlowStats {
            key: FlowKey {
                src: "10.0.0.1".parse().unwrap(),
                dst: "10.0.0.2".parse().unwrap(),
                src_port: 1234,
                dst_port: 80,
                proto: L4Proto::Tcp,
            },
            total_packets: 1,
            total_bytes: 50,
            a_to_b: DirStats { packets: 1, bytes: 50 },
            b_to_a: DirStats::default(),
            packet_indices: vec![],
            analysis: None,
            first_ts: Some(start),
            last_ts: Some(end),
        };

        let ip_host = HashMap::new();
        let _line = build_gantt_row(&fl, &[], &ip_host, start, end, 1, 10, false);
        let _line = build_gantt_row(&fl, &[], &ip_host, start, end, 0, 10, false);
    }

    #[test]
    fn build_scatter_row_places_markers() {
        use crate::flow::{DirStats, FlowStats};
        use crate::pcap::FlowKey;

        let start = Utc.timestamp_millis_opt(0).unwrap();
        let end = Utc.timestamp_millis_opt(1000).unwrap();

        let rows = vec![
            {
                let mut r = mk_packet_row(0, 100);
                r.flow_dir = Some(FlowDir::AtoB);
                r
            },
            {
                let mut r = mk_packet_row(1, 500);
                r.flow_dir = Some(FlowDir::BtoA);
                r
            },
        ];

        let fl = FlowStats {
            key: FlowKey {
                src: "10.0.0.1".parse().unwrap(),
                dst: "10.0.0.2".parse().unwrap(),
                src_port: 1234,
                dst_port: 80,
                proto: L4Proto::Tcp,
            },
            total_packets: 2,
            total_bytes: 120,
            a_to_b: DirStats { packets: 1, bytes: 60 },
            b_to_a: DirStats { packets: 1, bytes: 60 },
            packet_indices: vec![0, 1],
            analysis: None,
            first_ts: Some(Utc.timestamp_millis_opt(100).unwrap()),
            last_ts: Some(Utc.timestamp_millis_opt(500).unwrap()),
        };

        let ip_host = HashMap::new();
        let line = build_scatter_row(&fl, &rows, &ip_host, start, end, 20, 18, false);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        let dot_count = text.chars().filter(|&c| c == '●').count();
        assert!(dot_count >= 2, "Scatter row should have at least 2 markers, got {dot_count}");
    }

    #[test]
    fn narrative_for_tcp_flow_has_steps() {
        use crate::flow::{DirStats, FlowStats, FlowAnalysis, HealthBadge, TcpTiming};
        use crate::pcap::FlowKey;

        let rows = vec![
            {
                let mut r = mk_packet_row(0, 0);
                r.tcp_flags = Some(TCP_FLAG_SYN);
                r
            },
            {
                let mut r = mk_packet_row(1, 50);
                r.tcp_flags = Some(TCP_FLAG_SYN | TCP_FLAG_ACK);
                r
            },
            {
                let mut r = mk_packet_row(2, 100);
                r.tcp_flags = Some(TCP_FLAG_ACK);
                r.payload = vec![0u8; 100];
                r
            },
        ];

        let fl = FlowStats {
            key: FlowKey {
                src: "10.0.0.1".parse().unwrap(),
                dst: "93.184.216.34".parse().unwrap(),
                src_port: 50000,
                dst_port: 443,
                proto: L4Proto::Tcp,
            },
            total_packets: 3,
            total_bytes: 180,
            a_to_b: DirStats { packets: 3, bytes: 180 },
            b_to_a: DirStats::default(),
            packet_indices: vec![0, 1, 2],
            analysis: Some(FlowAnalysis {
                health: HealthBadge::Green,
                asymmetry: crate::flow::AsymmetryLabel::Balanced,
                tcp_timing: Some(TcpTiming {
                    handshake_rtt_us: Some(50_000),
                    server_think_us: None,
                    data_transfer_us: None,
                }),
            }),
            first_ts: Some(Utc.timestamp_millis_opt(0).unwrap()),
            last_ts: Some(Utc.timestamp_millis_opt(100).unwrap()),
        };

        let mut ip_host = HashMap::new();
        ip_host.insert("93.184.216.34".parse().unwrap(), "example.com".to_string());

        let lines = build_narrative(&fl, &rows, &ip_host);
        let text: String = lines.iter().map(|l| l.to_string()).collect::<Vec<_>>().join("\n");
        assert!(text.contains("example.com"), "Narrative should mention hostname");
        assert!(text.contains("50.0ms"), "Narrative should mention RTT");
        assert!(text.contains("Connected"), "Narrative should describe connection");
    }

    #[test]
    fn narrative_uses_neutral_direction_when_local_side_is_ambiguous() {
        use crate::flow::{AsymmetryLabel, DirStats, FlowAnalysis, FlowStats, HealthBadge};
        use crate::pcap::FlowKey;

        let rows = vec![mk_packet_row(0, 0)];
        let fl = FlowStats {
            key: FlowKey {
                src: "93.184.216.34".parse().unwrap(),
                dst: "198.51.100.10".parse().unwrap(),
                src_port: 443,
                dst_port: 50000,
                proto: L4Proto::Tcp,
            },
            total_packets: 1,
            total_bytes: 60,
            a_to_b: DirStats { packets: 1, bytes: 40 },
            b_to_a: DirStats { packets: 1, bytes: 20 },
            packet_indices: vec![0],
            analysis: Some(FlowAnalysis {
                health: HealthBadge::Green,
                asymmetry: AsymmetryLabel::AtoBHeavy,
                tcp_timing: None,
            }),
            first_ts: Some(Utc.timestamp_millis_opt(0).unwrap()),
            last_ts: Some(Utc.timestamp_millis_opt(0).unwrap()),
        };

        let ip_host = HashMap::new();
        let text = build_narrative(&fl, &rows, &ip_host)
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("A->B-heavy"), "Narrative should keep neutral canonical label");
        assert!(
            !text.contains("Mostly downloading") && !text.contains("Mostly uploading"),
            "Narrative should not claim upload/download when side inference is ambiguous",
        );
    }

    #[test]
    fn detect_patterns_dns_tls_requires_matching_hostname() {
        use crate::flow::{DirStats, FlowStats};
        use crate::pcap::FlowKey;

        let mut dns_row = mk_packet_row(0, 0);
        dns_row.proto = Some(L4Proto::Udp);
        dns_row.src_port = Some(53000);
        dns_row.dst_port = Some(53);
        dns_row.dns_qname = Some("unrelated.example".to_string());

        let mut tls_row = mk_packet_row(1, 2_000);
        tls_row.proto = Some(L4Proto::Tcp);
        tls_row.src_port = Some(51000);
        tls_row.dst_port = Some(443);
        tls_row.dst = Some("93.184.216.34".parse().unwrap());

        let flows = vec![
            FlowStats {
                key: FlowKey {
                    src: "10.0.0.1".parse().unwrap(),
                    dst: "1.1.1.1".parse().unwrap(),
                    src_port: 53000,
                    dst_port: 53,
                    proto: L4Proto::Udp,
                },
                total_packets: 1,
                total_bytes: 60,
                a_to_b: DirStats { packets: 1, bytes: 60 },
                b_to_a: DirStats::default(),
                packet_indices: vec![0],
                analysis: None,
                first_ts: Some(Utc.timestamp_millis_opt(0).unwrap()),
                last_ts: Some(Utc.timestamp_millis_opt(0).unwrap()),
            },
            FlowStats {
                key: FlowKey {
                    src: "10.0.0.1".parse().unwrap(),
                    dst: "93.184.216.34".parse().unwrap(),
                    src_port: 51000,
                    dst_port: 443,
                    proto: L4Proto::Tcp,
                },
                total_packets: 1,
                total_bytes: 120,
                a_to_b: DirStats { packets: 1, bytes: 120 },
                b_to_a: DirStats::default(),
                packet_indices: vec![1],
                analysis: None,
                first_ts: Some(Utc.timestamp_millis_opt(2_000).unwrap()),
                last_ts: Some(Utc.timestamp_millis_opt(2_000).unwrap()),
            },
        ];

        let mut app = App::new("/tmp/t.pcap", vec![dns_row, tls_row], crate::flow::FlowIndex { flows });
        app.visible_flow_indices = vec![0, 1];
        let sorted = vec![0, 1];

        let mut ip_host = HashMap::new();
        ip_host.insert("93.184.216.34".parse().unwrap(), "example.com".to_string());

        let lines = detect_patterns(&app, &sorted, &ip_host);
        let text = lines.iter().map(|l| l.to_string()).collect::<Vec<_>>().join("\n");
        assert!(
            !text.contains("preceded"),
            "Should not claim DNS preceded TLS without hostname match: {text}",
        );
    }

    #[test]
    fn detect_patterns_dns_tls_reports_when_hostname_matches() {
        use crate::flow::{DirStats, FlowStats};
        use crate::pcap::FlowKey;

        let mut dns_row = mk_packet_row(0, 0);
        dns_row.proto = Some(L4Proto::Udp);
        dns_row.src_port = Some(53000);
        dns_row.dst_port = Some(53);
        dns_row.dns_qname = Some("example.com".to_string());

        let mut tls_row = mk_packet_row(1, 2_000);
        tls_row.proto = Some(L4Proto::Tcp);
        tls_row.src_port = Some(51000);
        tls_row.dst_port = Some(443);
        tls_row.dst = Some("93.184.216.34".parse().unwrap());

        let flows = vec![
            FlowStats {
                key: FlowKey {
                    src: "10.0.0.1".parse().unwrap(),
                    dst: "1.1.1.1".parse().unwrap(),
                    src_port: 53000,
                    dst_port: 53,
                    proto: L4Proto::Udp,
                },
                total_packets: 1,
                total_bytes: 60,
                a_to_b: DirStats { packets: 1, bytes: 60 },
                b_to_a: DirStats::default(),
                packet_indices: vec![0],
                analysis: None,
                first_ts: Some(Utc.timestamp_millis_opt(0).unwrap()),
                last_ts: Some(Utc.timestamp_millis_opt(0).unwrap()),
            },
            FlowStats {
                key: FlowKey {
                    src: "10.0.0.1".parse().unwrap(),
                    dst: "93.184.216.34".parse().unwrap(),
                    src_port: 51000,
                    dst_port: 443,
                    proto: L4Proto::Tcp,
                },
                total_packets: 1,
                total_bytes: 120,
                a_to_b: DirStats { packets: 1, bytes: 120 },
                b_to_a: DirStats::default(),
                packet_indices: vec![1],
                analysis: None,
                first_ts: Some(Utc.timestamp_millis_opt(2_000).unwrap()),
                last_ts: Some(Utc.timestamp_millis_opt(2_000).unwrap()),
            },
        ];

        let mut app = App::new("/tmp/t.pcap", vec![dns_row, tls_row], crate::flow::FlowIndex { flows });
        app.visible_flow_indices = vec![0, 1];
        let sorted = vec![0, 1];

        let mut ip_host = HashMap::new();
        ip_host.insert("93.184.216.34".parse().unwrap(), "example.com".to_string());

        let lines = detect_patterns(&app, &sorted, &ip_host);
        let text = lines.iter().map(|l| l.to_string()).collect::<Vec<_>>().join("\n");
        assert!(text.contains("preceded"), "Expected DNS->TLS pattern callout, got: {text}");
    }
}
