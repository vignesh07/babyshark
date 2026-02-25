use super::{c_accent, c_muted, c_panel, c_text, centered_rect, match_cap_suffix, App};
use ratatui::layout::Margin;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

pub(super) const STREAM_SEARCH_MODAL_TITLE: &str = "Stream search";
pub(super) const STREAM_SEARCH_MODAL_HELP: &str =
    "Enter = apply   Esc = cancel   Ctrl+u = clear   (n/N next/prev, Tab/Shift-Tab switch stream)";
pub(super) const STREAM_SEARCH_STATUS_TYPE_TO_SEARCH: &str = "type to search";
pub(super) const STREAM_SEARCH_STATUS_MATCH_FOUND: &str = "match found (n/N to navigate)";
pub(super) const STREAM_SEARCH_STATUS_NO_MATCHES: &str = "no matches";

pub(super) fn build_explain_lines(app: &App) -> Vec<Line<'static>> {
    let Some(fl) = app.selected_flow() else {
        return vec![Line::from(Span::styled(
            "No flow selected.",
            Style::default().fg(c_muted()),
        ))];
    };

    let ex = crate::explain::explain_flow(&app.rows, fl);

    let mut out: Vec<Line> = Vec::new();
    out.push(Line::from(vec![Span::styled(
        ex.title,
        Style::default().fg(c_accent()).add_modifier(Modifier::BOLD),
    )]));
    out.push(Line::from(Span::raw("")));

    out.push(Line::from(vec![
        Span::styled("Likely: ", Style::default().fg(c_muted())),
        Span::styled(
            ex.likely,
            Style::default().fg(c_text()).add_modifier(Modifier::BOLD),
        ),
    ]));

    if !ex.why.is_empty() {
        out.push(Line::from(Span::raw("")));
        out.push(Line::from(Span::styled(
            "Why I think that:",
            Style::default().fg(c_muted()).add_modifier(Modifier::BOLD),
        )));
        for w in ex.why.iter().take(8) {
            out.push(Line::from(vec![
                Span::styled("• ", Style::default().fg(c_muted())),
                Span::styled(w.to_string(), Style::default().fg(c_text())),
            ]));
        }
    }

    if !ex.next.is_empty() {
        out.push(Line::from(Span::raw("")));
        out.push(Line::from(Span::styled(
            "Next steps:",
            Style::default().fg(c_muted()).add_modifier(Modifier::BOLD),
        )));
        for n in ex.next.iter().take(8) {
            out.push(Line::from(vec![
                Span::styled("• ", Style::default().fg(c_muted())),
                Span::styled(n.to_string(), Style::default().fg(c_text())),
            ]));
        }
    }

    out.push(Line::from(Span::raw("")));
    out.push(Line::from(Span::styled(
        "Esc to close",
        Style::default().fg(c_muted()),
    )));

    out
}

pub(super) fn render_explain_modal(
    f: &mut ratatui::Frame,
    size: ratatui::layout::Rect,
    lines: &[Line<'static>],
) {
    let area = centered_rect(80, 60, size);
    f.render_widget(Clear, area);
    let inner = area.inner(Margin {
        horizontal: 2,
        vertical: 1,
    });

    let block = Block::default()
        .borders(Borders::ALL)
        .title("Explain")
        .style(Style::default().bg(c_panel()).fg(c_text()));
    f.render_widget(block, area);

    let p = Paragraph::new(lines.to_vec())
        .wrap(Wrap { trim: true })
        .style(Style::default().bg(c_panel()).fg(c_text()));
    f.render_widget(p, inner);
}

pub(super) fn build_glossary_lines() -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(
            "Glossary",
            Style::default().fg(c_accent()).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::raw("")),
        Line::from(Span::styled(
            "TCP flags",
            Style::default().fg(c_muted()).add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled("• SYN: ", Style::default().fg(c_muted())),
            Span::styled("Start a TCP connection.", Style::default().fg(c_text())),
        ]),
        Line::from(vec![
            Span::styled("• ACK: ", Style::default().fg(c_muted())),
            Span::styled(
                "Acknowledges received bytes.",
                Style::default().fg(c_text()),
            ),
        ]),
        Line::from(vec![
            Span::styled("• FIN: ", Style::default().fg(c_muted())),
            Span::styled("Graceful close.", Style::default().fg(c_text())),
        ]),
        Line::from(vec![
            Span::styled("• RST: ", Style::default().fg(c_muted())),
            Span::styled("Abort / refused connection.", Style::default().fg(c_text())),
        ]),
        Line::from(Span::raw("")),
        Line::from(Span::styled(
            "DNS failure codes",
            Style::default().fg(c_muted()).add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled("• NXDOMAIN: ", Style::default().fg(c_muted())),
            Span::styled("Name does not exist.", Style::default().fg(c_text())),
        ]),
        Line::from(vec![
            Span::styled("• SERVFAIL: ", Style::default().fg(c_muted())),
            Span::styled("Resolver error.", Style::default().fg(c_text())),
        ]),
        Line::from(Span::raw("")),
        Line::from(Span::styled(
            "Protocols",
            Style::default().fg(c_muted()).add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled("• TCP: ", Style::default().fg(c_muted())),
            Span::styled(
                "Reliable, ordered stream (retransmits on loss).",
                Style::default().fg(c_text()),
            ),
        ]),
        Line::from(vec![
            Span::styled("• UDP: ", Style::default().fg(c_muted())),
            Span::styled(
                "Unreliable datagrams (no built-in retransmit).",
                Style::default().fg(c_text()),
            ),
        ]),
        Line::from(vec![
            Span::styled("• QUIC: ", Style::default().fg(c_muted())),
            Span::styled(
                "Reliable transport over UDP (used by HTTP/3).",
                Style::default().fg(c_text()),
            ),
        ]),
        Line::from(Span::raw("")),
        Line::from(Span::styled(
            "Streams",
            Style::default().fg(c_muted()).add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled("• Follow stream: ", Style::default().fg(c_muted())),
            Span::styled(
                "Reassembled payload bytes for a TCP flow direction (best-effort).",
                Style::default().fg(c_text()),
            ),
        ]),
        Line::from(vec![
            Span::styled("• TLS note: ", Style::default().fg(c_muted())),
            Span::styled(
                "HTTPS payload is encrypted; without keys you typically can’t inspect contents.",
                Style::default().fg(c_text()),
            ),
        ]),
        Line::from(Span::raw("")),
        Line::from(Span::styled(
            "Esc/Backspace to close",
            Style::default().fg(c_muted()),
        )),
    ]
}

pub(super) fn render_glossary_modal(
    f: &mut ratatui::Frame,
    size: ratatui::layout::Rect,
    lines: &[Line<'static>],
) {
    let area = centered_rect(80, 60, size);
    f.render_widget(Clear, area);
    let inner = area.inner(Margin {
        horizontal: 2,
        vertical: 1,
    });

    let block = Block::default()
        .borders(Borders::ALL)
        .title("Glossary")
        .style(Style::default().bg(c_panel()).fg(c_text()));
    f.render_widget(block, area);

    let p = Paragraph::new(lines.to_vec())
        .wrap(Wrap { trim: true })
        .style(Style::default().bg(c_panel()).fg(c_text()));
    f.render_widget(p, inner);
}

pub(super) fn build_help_lines() -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(
            "Start here",
            Style::default().fg(c_accent()).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::raw("")),
        Line::from(vec![
            Span::styled("o ", Style::default().fg(Color::Green)),
            Span::styled("Overview", Style::default().fg(c_text())),
            Span::styled("  (what’s going on)", Style::default().fg(c_muted())),
        ]),
        Line::from(vec![
            Span::styled("D ", Style::default().fg(Color::Green)),
            Span::styled("Domains", Style::default().fg(c_text())),
            Span::styled("  (hostnames + drill down)", Style::default().fg(c_muted())),
        ]),
        Line::from(vec![
            Span::styled("W ", Style::default().fg(Color::Green)),
            Span::styled("Weird stuff", Style::default().fg(c_text())),
            Span::styled("  (troubleshoot)", Style::default().fg(c_muted())),
        ]),
        Line::from(vec![
            Span::styled("F ", Style::default().fg(Color::Green)),
            Span::styled("Flows", Style::default().fg(c_text())),
            Span::styled("  (raw)", Style::default().fg(c_muted())),
        ]),
        Line::from(vec![
            Span::styled("G ", Style::default().fg(Color::Green)),
            Span::styled("Timeline", Style::default().fg(c_text())),
            Span::styled("  (Gantt + Scatter)", Style::default().fg(c_muted())),
        ]),
        Line::from(Span::raw("")),
        Line::from(Span::styled(
            "Universal keys",
            Style::default().fg(c_muted()).add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled("Enter", Style::default().fg(Color::Green)),
            Span::styled(" drill down", Style::default().fg(c_text())),
            Span::styled("   ", Style::default()),
            Span::styled("Esc", Style::default().fg(Color::Green)),
            Span::styled(" back", Style::default().fg(c_text())),
        ]),
        Line::from(vec![
            Span::styled("/", Style::default().fg(Color::Green)),
            Span::styled(" filter (Flows)", Style::default().fg(c_text())),
            Span::styled("   ", Style::default()),
            Span::styled("c", Style::default().fg(Color::Green)),
            Span::styled(" clear subset", Style::default().fg(c_text())),
        ]),
        Line::from(vec![
            Span::styled("?", Style::default().fg(Color::Green)),
            Span::styled(" explain", Style::default().fg(c_text())),
            Span::styled("   ", Style::default()),
            Span::styled("g", Style::default().fg(Color::Green)),
            Span::styled(" glossary", Style::default().fg(c_text())),
            Span::styled("   ", Style::default()),
            Span::styled("L", Style::default().fg(Color::Green)),
            Span::styled(" learning", Style::default().fg(c_text())),
        ]),
        Line::from(Span::raw("")),
        Line::from(Span::styled("Esc to close", Style::default().fg(c_muted()))),
    ]
}

pub(super) fn render_help_modal(
    f: &mut ratatui::Frame,
    size: ratatui::layout::Rect,
    lines: &[Line<'static>],
) {
    let area = centered_rect(80, 60, size);
    f.render_widget(Clear, area);
    let inner = area.inner(Margin {
        horizontal: 2,
        vertical: 1,
    });

    let block = Block::default()
        .borders(Borders::ALL)
        .title("Help")
        .style(Style::default().bg(c_panel()).fg(c_text()));
    f.render_widget(block, area);

    let p = Paragraph::new(lines.to_vec())
        .wrap(Wrap { trim: true })
        .style(Style::default().bg(c_panel()).fg(c_text()));
    f.render_widget(p, inner);
}

pub(super) fn render_search_modal(
    f: &mut ratatui::Frame,
    size: ratatui::layout::Rect,
    input: &str,
    match_count: usize,
    has_match: bool,
) {
    let area = centered_rect(70, 22, size);
    f.render_widget(Clear, area);
    let inner = area.inner(Margin {
        horizontal: 2,
        vertical: 1,
    });

    let block = Block::default()
        .borders(Borders::ALL)
        .title(STREAM_SEARCH_MODAL_TITLE)
        .style(Style::default().bg(c_panel()).fg(c_text()));
    f.render_widget(block, area);

    let q = if input.is_empty() { "(empty)" } else { input };

    let status = if input.is_empty() {
        STREAM_SEARCH_STATUS_TYPE_TO_SEARCH
    } else if has_match {
        STREAM_SEARCH_STATUS_MATCH_FOUND
    } else {
        STREAM_SEARCH_STATUS_NO_MATCHES
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Query: ", Style::default().fg(c_muted())),
            Span::raw(q.to_string()),
        ]),
        Line::from(Span::raw("")),
        Line::from(vec![
            Span::styled("Status: ", Style::default().fg(c_muted())),
            Span::styled(
                status,
                Style::default().fg(if input.is_empty() {
                    c_muted()
                } else if has_match {
                    Color::Green
                } else {
                    Color::Red
                }),
            ),
        ]),
        Line::from(vec![
            Span::styled("Matches: ", Style::default().fg(c_muted())),
            Span::styled(
                format!("{match_count}{}", match_cap_suffix(match_count)),
                Style::default().fg(if input.is_empty() {
                    c_muted()
                } else if match_count > 0 {
                    Color::Green
                } else {
                    Color::Red
                }),
            ),
        ]),
        Line::from(Span::raw("")),
        Line::from(Span::styled(
            STREAM_SEARCH_MODAL_HELP,
            Style::default().fg(c_muted()),
        )),
    ];

    // keep layout stable
    if lines.len() < 5 {
        lines.push(Line::from(Span::raw("")));
    }

    let p = Paragraph::new(lines)
        .wrap(Wrap { trim: true })
        .style(Style::default().bg(c_panel()).fg(c_text()));
    f.render_widget(p, inner);
}
