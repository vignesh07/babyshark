use chrono::{DateTime, Utc};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use super::{c_highlight_bg, c_muted, c_text, App, TimelineTab};
use crate::flow::{FlowStats, HealthBadge};
use crate::pcap::FlowDir;

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

/// Returns (first_ts, last_ts) from the capture's first/last rows.
/// Returns None if capture has fewer than 2 rows or zero duration.
pub(super) fn capture_time_range(app: &App) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    if app.rows.len() < 2 {
        return None;
    }
    let first = app.rows.first()?.ts;
    let last = app.rows.last()?.ts;
    if first >= last {
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

fn truncated_label(fl: &FlowStats, width: usize) -> String {
    let full = fl.label();
    if full.len() <= width {
        format!("{:<width$}", full, width = width)
    } else {
        let mut s = full[..width.saturating_sub(1)].to_string();
        s.push('…');
        s
    }
}

/// Build a single Gantt row: label + badge + horizontal bar.
pub(super) fn build_gantt_row(
    fl: &FlowStats,
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

    spans.push(Span::styled(truncated_label(fl, label_width), base_style));
    spans.push(health_badge_span(fl));

    if bar_width < 2 {
        return Line::from(spans);
    }

    let color = health_color(fl);

    let (flow_start, flow_end) = match (fl.first_ts, fl.last_ts) {
        (Some(s), Some(e)) => (s, e),
        _ => return Line::from(spans),
    };

    let start_col = ts_to_col(flow_start, capture_start, capture_end, bar_width);
    let end_col = ts_to_col(flow_end, capture_start, capture_end, bar_width);

    let mut bar = String::with_capacity(bar_width);
    for c in 0..bar_width {
        if c >= start_col && c <= end_col {
            bar.push('█');
        } else {
            bar.push(' ');
        }
    }

    spans.push(Span::styled(bar, Style::default().fg(color)));

    Line::from(spans)
}

/// Build a single Scatter row: label + per-packet dots.
pub(super) fn build_scatter_row(
    fl: &FlowStats,
    rows: &[crate::pcap::PacketRow],
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

    spans.push(Span::styled(truncated_label(fl, label_width), base_style));
    spans.push(health_badge_span(fl));

    if bar_width < 2 {
        return Line::from(spans);
    }

    // For each column, track what kind of packet(s) land there.
    // 0 = empty, 1 = AtoB, 2 = BtoA, 3 = retransmit/OOO, 4 = collision (multiple)
    let mut grid: Vec<u8> = vec![0; bar_width];
    let mut counts: Vec<u16> = vec![0; bar_width];

    for &pi in &fl.packet_indices {
        let Some(r) = rows.get(pi) else { continue };
        let col = ts_to_col(r.ts, capture_start, capture_end, bar_width);
        counts[col] += 1;

        if r.tcp_retransmission || r.tcp_out_of_order {
            grid[col] = 3; // retransmit takes priority color
        } else if grid[col] == 0 {
            grid[col] = match r.flow_dir {
                Some(FlowDir::AtoB) => 1,
                Some(FlowDir::BtoA) => 2,
                None => 1,
            };
        } else if grid[col] != 3 {
            // already has a packet; could be same or different direction
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

/// Build all timeline items: returns (time_axis_header, flow_rows).
/// Flows are sorted by first_ts for a coherent timeline.
pub(super) fn build_timeline_items(
    app: &App,
    tab: TimelineTab,
    bar_width: usize,
    label_width: usize,
    selected_row: usize,
) -> (Line<'static>, Vec<Line<'static>>) {
    let Some((capture_start, capture_end)) = capture_time_range(app) else {
        return (
            Line::from(Span::styled(
                "Not enough data for timeline",
                Style::default().fg(c_muted()),
            )),
            Vec::new(),
        );
    };

    let axis = build_time_axis(capture_start, capture_end, bar_width, label_width);

    // Sort visible flows by first_ts
    let mut sorted_indices: Vec<usize> = app.visible_flow_indices.clone();
    sorted_indices.sort_by(|&a, &b| {
        let fa = app.flows.flows.get(a).and_then(|f| f.first_ts);
        let fb = app.flows.flows.get(b).and_then(|f| f.first_ts);
        fa.cmp(&fb)
    });

    let rows: Vec<Line> = sorted_indices
        .iter()
        .enumerate()
        .map(|(i, &flow_idx)| {
            let fl = &app.flows.flows[flow_idx];
            let is_selected = i == selected_row;
            match tab {
                TimelineTab::Gantt => {
                    build_gantt_row(fl, capture_start, capture_end, bar_width, label_width, is_selected)
                }
                TimelineTab::Scatter => {
                    build_scatter_row(fl, &app.rows, capture_start, capture_end, bar_width, label_width, is_selected)
                }
            }
        })
        .collect();

    (axis, rows)
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

    #[test]
    fn ts_to_col_boundaries() {
        let start = Utc.timestamp_millis_opt(0).unwrap();
        let end = Utc.timestamp_millis_opt(1000).unwrap();

        // Start maps to col 0
        assert_eq!(ts_to_col(start, start, end, 10), 0);
        // End maps to last col
        assert_eq!(ts_to_col(end, start, end, 10), 9);
        // Midpoint maps to middle
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
    fn build_gantt_row_produces_correct_width() {
        use crate::flow::{DirStats, FlowStats};
        use crate::pcap::{FlowKey, L4Proto};

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
            total_packets: 2,
            total_bytes: 100,
            a_to_b: DirStats { packets: 1, bytes: 50 },
            b_to_a: DirStats { packets: 1, bytes: 50 },
            packet_indices: vec![],
            analysis: None,
            first_ts: Some(Utc.timestamp_millis_opt(200).unwrap()),
            last_ts: Some(Utc.timestamp_millis_opt(800).unwrap()),
        };

        let line = build_gantt_row(&fl, start, end, 20, 18, false);
        // The line should contain bar characters
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        let bar_count = text.chars().filter(|&c| c == '█').count();
        assert!(bar_count > 0, "Gantt row should have bar characters");
        assert!(bar_count <= 20, "Bar should not exceed bar_width");
    }

    #[test]
    fn narrow_bar_width_does_not_panic() {
        use crate::flow::{DirStats, FlowStats};
        use crate::pcap::{FlowKey, L4Proto};

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

        // Very narrow: should not panic
        let _line = build_gantt_row(&fl, start, end, 1, 10, false);
        let _line = build_gantt_row(&fl, start, end, 0, 10, false);
    }

    #[test]
    fn build_scatter_row_places_markers() {
        use crate::flow::{DirStats, FlowStats};
        use crate::pcap::{FlowDir, FlowKey, L4Proto, PacketRow};

        let start = Utc.timestamp_millis_opt(0).unwrap();
        let end = Utc.timestamp_millis_opt(1000).unwrap();

        let rows = vec![
            PacketRow {
                index: 0,
                ts: Utc.timestamp_millis_opt(100).unwrap(),
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
            },
            PacketRow {
                index: 1,
                ts: Utc.timestamp_millis_opt(500).unwrap(),
                len: 60,
                src: Some("10.0.0.2".parse().unwrap()),
                dst: Some("10.0.0.1".parse().unwrap()),
                proto: Some(L4Proto::Tcp),
                src_port: Some(80),
                dst_port: Some(1234),
                summary: String::new(),
                flow: None,
                flow_dir: Some(FlowDir::BtoA),
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

        let line = build_scatter_row(&fl, &rows, start, end, 20, 18, false);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        let dot_count = text.chars().filter(|&c| c == '●').count();
        assert!(dot_count >= 2, "Scatter row should have at least 2 markers, got {dot_count}");
    }
}
