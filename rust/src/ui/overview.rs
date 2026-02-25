use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use super::hexdump::UI_SPACER;
use super::{c_accent, c_muted, c_text, App};

#[derive(Debug, Clone)]
pub(super) enum OverviewAction {
    GoFlows,
    GoWeird,
    Port(u16),
    Host(std::net::IpAddr),
    FlowIndex(usize),
}

#[derive(Debug, Clone)]
pub(super) struct OverviewRow {
    pub label: Line<'static>,
    pub action: Option<OverviewAction>,
}

pub(super) fn build_overview_rows(app: &App) -> Vec<OverviewRow> {
    use crate::summary::build_overview;

    let ov = build_overview(&app.rows, &app.flows, 10);
    let weird = crate::weird::build_weird_summary(&app.rows, &app.flows);

    let mut rows: Vec<OverviewRow> = Vec::new();

    if app.show_onboarding {
        rows.push(OverviewRow {
            label: Line::from(vec![Span::styled(
                "New here?",
                Style::default()
                    .fg(Color::Rgb(255, 215, 0))
                    .add_modifier(Modifier::BOLD),
            )]),
            action: None,
        });
        rows.push(OverviewRow {
            label: Line::from(vec![
                Span::styled("• ", Style::default().fg(c_muted())),
                Span::styled(
                    "Press D",
                    Style::default().fg(c_accent()).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" for Domains (human view)", Style::default().fg(c_text())),
            ]),
            action: None,
        });
        rows.push(OverviewRow {
            label: Line::from(vec![
                Span::styled("• ", Style::default().fg(c_muted())),
                Span::styled(
                    "Press W",
                    Style::default().fg(c_accent()).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    " for Weird stuff (troubleshoot)",
                    Style::default().fg(c_text()),
                ),
            ]),
            action: None,
        });
        rows.push(OverviewRow {
            label: Line::from(vec![
                Span::styled("• ", Style::default().fg(c_muted())),
                Span::styled(
                    "Press F",
                    Style::default().fg(c_accent()).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" for Flows (raw)", Style::default().fg(c_text())),
            ]),
            action: None,
        });
        rows.push(OverviewRow {
            label: Line::from(vec![
                Span::styled("• ", Style::default().fg(c_muted())),
                Span::styled(
                    "Press h",
                    Style::default().fg(c_accent()).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" for help, g for glossary", Style::default().fg(c_text())),
                Span::styled("  (x dismiss)", Style::default().fg(c_muted())),
            ]),
            action: None,
        });
        rows.push(OverviewRow {
            label: Line::from(Span::raw("")),
            action: None,
        });
    }

    rows.push(OverviewRow {
        label: Line::from(vec![Span::styled(
            "In plain English",
            Style::default().fg(c_text()).add_modifier(Modifier::BOLD),
        )]),
        action: None,
    });

    let top_talker = ov
        .top_hosts
        .first()
        .map(|(ip, c)| format!("{ip} ({:.1}KB)", (c.bytes as f64) / 1024.0))
        .unwrap_or_else(|| "—".to_string());

    let top_talker_by_packets = ov
        .top_hosts_by_packets
        .first()
        .map(|(ip, c)| format!("{ip} ({} pkts)", c.packets))
        .unwrap_or_else(|| "—".to_string());
    let top_flow = ov
        .top_flows
        .first()
        .map(|f| format!("{} ({:.1}KB)", f.label(), (f.total_bytes as f64) / 1024.0))
        .unwrap_or_else(|| "—".to_string());

    let top_flow_by_packets = ov
        .top_flows_by_packets
        .first()
        .map(|f| format!("{} ({} pkts)", f.label(), f.total_packets))
        .unwrap_or_else(|| "—".to_string());

    rows.push(OverviewRow {
        label: Line::from(Span::styled(
            format!(
                "Packets: {}   Flows: {}   Top talker: {top_talker}   Top talker (pkts): {top_talker_by_packets}",
                ov.total_packets,
                app.flows.flows.len()
            ),
            Style::default().fg(c_muted()),
        )),
        action: None,
    });

    if app.live_iface.is_some() {
        let secs = app.live_capture_start.elapsed().as_secs();
        let dropped = app.live_dropped_packets;
        let mut msg = format!(
            "Live: {secs}s   pps~{:.1}   dropped~{dropped}",
            app.live_pps
        );
        if let Some(e) = &app.live_last_stderr {
            // Keep it short; the details panel can show full errors later.
            msg.push_str("   | last: ");
            msg.push_str(&e.chars().take(60).collect::<String>());
        }
        rows.push(OverviewRow {
            label: Line::from(Span::styled(msg, Style::default().fg(c_muted()))),
            action: None,
        });
    }

    // Packets/sec sparkline (coarse buckets).
    if !ov.pps_buckets.is_empty() {
        let max = ov.pps_buckets.iter().copied().max().unwrap_or(0);
        let glyphs: [char; 9] = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
        let spark: String = if max == 0 {
            "".to_string()
        } else {
            ov.pps_buckets
                .iter()
                .map(|v| {
                    let idx = ((*v as u64) * 8 / (max as u64)).min(8) as usize;
                    glyphs[idx]
                })
                .collect()
        };

        rows.push(OverviewRow {
            label: Line::from(Span::styled(
                format!("pps: {spark}  (max {max}/bucket)"),
                Style::default().fg(c_muted()),
            )),
            action: None,
        });
    }
    rows.push(OverviewRow {
        label: Line::from(Span::styled(
            format!("Top flow (bytes): {top_flow}"),
            Style::default().fg(c_muted()),
        )),
        action: None,
    });

    rows.push(OverviewRow {
        label: Line::from(Span::styled(
            format!("Top flow (pkts): {top_flow_by_packets}"),
            Style::default().fg(c_muted()),
        )),
        action: None,
    });
    rows.push(OverviewRow {
        label: Line::from(Span::raw("")),
        action: None,
    });

    rows.push(OverviewRow {
        label: Line::from(vec![Span::styled(
            "What should I select?",
            Style::default().fg(c_text()).add_modifier(Modifier::BOLD),
        )]),
        action: None,
    });
    rows.push(OverviewRow {
        label: Line::from(vec![
            Span::styled("• ", Style::default().fg(c_muted())),
            Span::styled(
                "Domains (human view)",
                Style::default()
                    .fg(Color::Rgb(255, 215, 0))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  (press D)", Style::default().fg(c_muted())),
        ]),
        // Domains row uses a dedicated keybind; make it obvious even if Enter does nothing.
        action: None,
    });

    rows.push(OverviewRow {
        label: Line::from(vec![
            Span::styled("• ", Style::default().fg(c_muted())),
            Span::styled(
                "Weird stuff (troubleshoot)",
                Style::default()
                    .fg(Color::Rgb(255, 215, 0))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  (press W)", Style::default().fg(c_muted())),
        ]),
        action: Some(OverviewAction::GoWeird),
    });

    rows.push(OverviewRow {
        label: Line::from(vec![
            Span::styled("• ", Style::default().fg(c_muted())),
            Span::styled("Flows (raw)", Style::default().fg(c_accent())),
            Span::styled("  (press F)", Style::default().fg(c_muted())),
        ]),
        action: Some(OverviewAction::GoFlows),
    });

    if weird.items.iter().any(|it| !it.flow_indices.is_empty()) {
        let first = weird
            .items
            .iter()
            .find(|it| !it.flow_indices.is_empty())
            .map(|it| format!("{} ({} flows)", it.title, it.flow_indices.len()))
            .unwrap_or_else(|| "Weird stuff".to_string());
        rows.push(OverviewRow {
            label: Line::from(vec![
                Span::styled("  ↳ ", Style::default().fg(c_muted())),
                Span::styled(
                    format!("Detected: {first}"),
                    Style::default().fg(Color::Rgb(255, 215, 0)),
                ),
            ]),
            action: None,
        });
    }

    rows.push(OverviewRow {
        label: Line::from(Span::raw("")),
        action: None,
    });

    rows.push(OverviewRow {
        label: Line::from(vec![Span::styled(
            "Traffic mix",
            Style::default().fg(c_text()).add_modifier(Modifier::BOLD),
        )]),
        action: None,
    });
    rows.push(OverviewRow {
        label: Line::from(Span::styled(
            format!(
                "TCP: {}  UDP: {}  Other: {}",
                ov.protos.tcp, ov.protos.udp, ov.protos.other
            ),
            Style::default().fg(c_muted()),
        )),
        action: None,
    });
    rows.push(OverviewRow {
        label: Line::from(Span::raw("")),
        action: None,
    });

    rows.push(OverviewRow {
        label: Line::from(vec![Span::styled(
            "Top ports (select = filter flows)",
            Style::default().fg(c_text()).add_modifier(Modifier::BOLD),
        )]),
        action: None,
    });
    for (port, c) in ov.top_ports.iter().take(8) {
        rows.push(OverviewRow {
            label: Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(
                    format!("{port:>5}"),
                    Style::default().fg(c_accent()).add_modifier(Modifier::BOLD),
                ),
                Span::raw(UI_SPACER),
                Span::styled(
                    format!("bytes={:<10} pkts={}", c.bytes, c.packets),
                    Style::default().fg(c_text()),
                ),
            ]),
            action: Some(OverviewAction::Port(*port)),
        });
    }
    rows.push(OverviewRow {
        label: Line::from(Span::raw("")),
        action: None,
    });

    rows.push(OverviewRow {
        label: Line::from(vec![Span::styled(
            "Top hosts (IPv4 only)",
            Style::default().fg(c_text()).add_modifier(Modifier::BOLD),
        )]),
        action: None,
    });
    for (ip, c) in ov.top_hosts.iter().take(8) {
        rows.push(OverviewRow {
            label: Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(
                    format!("{ip:<15}"),
                    Style::default().fg(c_accent()).add_modifier(Modifier::BOLD),
                ),
                Span::raw(UI_SPACER),
                Span::styled(
                    format!("bytes={:<10} pkts={}", c.bytes, c.packets),
                    Style::default().fg(c_text()),
                ),
            ]),
            action: Some(OverviewAction::Host(*ip)),
        });
    }
    rows.push(OverviewRow {
        label: Line::from(Span::raw("")),
        action: None,
    });

    rows.push(OverviewRow {
        label: Line::from(vec![Span::styled(
            "Top flows (select = jump)",
            Style::default().fg(c_text()).add_modifier(Modifier::BOLD),
        )]),
        action: None,
    });
    for (i, fl) in ov.top_flows.iter().take(6).enumerate() {
        rows.push(OverviewRow {
            label: Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(format!("#{:>2} ", i + 1), Style::default().fg(c_muted())),
                Span::styled(fl.label(), Style::default().fg(c_text())),
                Span::raw(UI_SPACER),
                Span::styled(
                    format!("{}B", fl.total_bytes),
                    Style::default().fg(c_muted()),
                ),
            ]),
            action: app
                .flows
                .flows
                .iter()
                .position(|f| f.key == fl.key)
                .map(OverviewAction::FlowIndex),
        });
    }

    rows
}
