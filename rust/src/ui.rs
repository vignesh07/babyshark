use crate::flow::{FlowIndex, FlowStats};
use crate::pcap::{FlowDir, PacketRow};
use crate::stream::{build_stream, StreamData};
use crate::ui_filter::FlowFilter;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::execute;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Margin};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Terminal;
use std::io::{self, Stdout};
use std::time::Duration;

// --- Theme (deep ocean) ---
fn c_bg() -> Color {
    Color::Rgb(10, 12, 18)
}
fn c_panel() -> Color {
    Color::Rgb(14, 18, 28)
}
fn c_accent() -> Color {
    Color::Rgb(64, 224, 208) // turquoise
}
fn c_highlight_bg() -> Color {
    Color::Rgb(24, 32, 52)
}
fn c_text() -> Color {
    Color::Rgb(230, 235, 245)
}
fn c_muted() -> Color {
    Color::Rgb(140, 150, 170)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Flows,
    Packets,
    Stream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamTab {
    AtoB,
    BtoA,
    Combined,
}

pub struct App {
    pub rows: Vec<PacketRow>,
    pub flows: FlowIndex,

    pub view: View,

    // flows selection is by index into `visible_flow_indices`
    pub selected_row: usize,
    pub visible_flow_indices: Vec<usize>,

    // filter
    pub filter: FlowFilter,
    pub filter_mode: bool,

    // stream view state
    pub stream_tab: StreamTab,
    pub stream_scroll: u16,
}

impl App {
    pub fn new(rows: Vec<PacketRow>, flows: FlowIndex) -> Self {
        let mut app = App {
            rows,
            flows,
            view: View::Flows,
            selected_row: 0,
            visible_flow_indices: Vec::new(),
            filter: FlowFilter::default(),
            filter_mode: false,
            stream_tab: StreamTab::Combined,
            stream_scroll: 0,
        };
        app.recompute_visible();
        app
    }

    fn recompute_visible(&mut self) {
        self.visible_flow_indices = self
            .flows
            .flows
            .iter()
            .enumerate()
            .filter(|(_i, f)| self.filter.matches(f))
            .map(|(i, _)| i)
            .collect();
        if self.selected_row >= self.visible_flow_indices.len() {
            self.selected_row = self.visible_flow_indices.len().saturating_sub(1);
        }
    }

    fn selected_flow(&self) -> Option<&FlowStats> {
        let i = *self.visible_flow_indices.get(self.selected_row)?;
        self.flows.flows.get(i)
    }

    fn move_down(&mut self) {
        if self.visible_flow_indices.is_empty() {
            self.selected_row = 0;
            return;
        }
        self.selected_row = (self.selected_row + 1).min(self.visible_flow_indices.len() - 1);
    }

    fn move_up(&mut self) {
        if self.visible_flow_indices.is_empty() {
            self.selected_row = 0;
            return;
        }
        self.selected_row = self.selected_row.saturating_sub(1);
    }

    fn open_packets(&mut self) {
        self.view = View::Packets;
    }

    fn open_stream(&mut self) {
        self.view = View::Stream;
        self.stream_scroll = 0;
    }

    fn back(&mut self) {
        self.view = match self.view {
            View::Flows => View::Flows,
            View::Packets => View::Flows,
            View::Stream => View::Packets,
        };
        self.stream_scroll = 0;
    }

    fn tab_next(&mut self) {
        self.stream_tab = match self.stream_tab {
            StreamTab::Combined => StreamTab::AtoB,
            StreamTab::AtoB => StreamTab::BtoA,
            StreamTab::BtoA => StreamTab::Combined,
        };
        self.stream_scroll = 0;
    }

    fn scroll_down(&mut self) {
        self.stream_scroll = self.stream_scroll.saturating_add(1);
    }

    fn scroll_up(&mut self) {
        self.stream_scroll = self.stream_scroll.saturating_sub(1);
    }

    fn toggle_tcp(&mut self) {
        self.filter.show_tcp = !self.filter.show_tcp;
        self.recompute_visible();
    }

    fn toggle_udp(&mut self) {
        self.filter.show_udp = !self.filter.show_udp;
        self.recompute_visible();
    }

    fn enter_filter_mode(&mut self) {
        self.filter_mode = true;
    }

    fn exit_filter_mode(&mut self) {
        self.filter_mode = false;
        self.recompute_visible();
    }

    fn filter_push(&mut self, c: char) {
        self.filter.query.push(c);
        self.recompute_visible();
    }

    fn filter_pop(&mut self) {
        self.filter.query.pop();
        self.recompute_visible();
    }

    fn filter_clear(&mut self) {
        self.filter.query.clear();
        self.recompute_visible();
    }
}

pub fn run_tui(app: &mut App) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_loop(&mut terminal, app);

    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();

    res
}

fn bytes_to_pretty_text(bytes: &[u8]) -> Text<'static> {
    let mut lines: Vec<Line> = Vec::new();
    let mut offset: usize = 0;
    while offset < bytes.len() {
        let chunk = &bytes[offset..bytes.len().min(offset + 16)];
        let hex = chunk
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii = chunk
            .iter()
            .map(|b| {
                let c = *b as char;
                if c.is_ascii_graphic() || c == ' ' {
                    c
                } else {
                    '.'
                }
            })
            .collect::<String>();
        lines.push(Line::from(vec![
            Span::styled(format!("{:08x}  ", offset), Style::default().fg(c_muted())),
            Span::styled(format!("{:<47}", hex), Style::default().fg(Color::Rgb(170, 180, 200))),
            Span::raw("  "),
            Span::styled(ascii, Style::default().fg(c_text())),
        ]));
        offset += 16;
    }
    Text::from(lines)
}

fn run_loop(terminal: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App) -> Result<()> {
    let mut flow_state = ListState::default();
    if !app.visible_flow_indices.is_empty() {
        flow_state.select(Some(app.selected_row));
    }

    loop {
        terminal.draw(|f| {
            let size = f.area();

            // base background
            let bg = Block::default().style(Style::default().bg(c_bg()));
            f.render_widget(bg, size);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(1), Constraint::Length(2)])
                .split(size);

            let title = match app.view {
                View::Flows => "Flows",
                View::Packets => "Packets",
                View::Stream => "Follow Stream",
            };

            let filter_badge = format!(
                "tcp:{} udp:{} q={}",
                if app.filter.show_tcp { "on" } else { "off" },
                if app.filter.show_udp { "on" } else { "off" },
                if app.filter.query.trim().is_empty() {
                    "—"
                } else {
                    app.filter.query.trim()
                }
            );

            let header = Paragraph::new(Line::from(vec![
                Span::styled("babyshark", Style::default().fg(c_accent()).add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::styled(title, Style::default().fg(c_text()).add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::styled(
                    format!("flows:{} packets:{}", app.visible_flow_indices.len(), app.rows.len()),
                    Style::default().fg(c_muted()),
                ),
                Span::raw("  "),
                Span::styled(filter_badge, Style::default().fg(c_muted())),
            ]))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("PCAP Viewer")
                    .style(Style::default().bg(c_panel())),
            );
            f.render_widget(header, chunks[0]);

            let body_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
                .split(chunks[1]);

            match app.view {
                View::Flows => {
                    let items: Vec<ListItem> = app
                        .visible_flow_indices
                        .iter()
                        .enumerate()
                        .filter_map(|(row_i, flow_i)| {
                            let fl = app.flows.flows.get(*flow_i)?;
                            let proto = match fl.key.proto {
                                crate::pcap::L4Proto::Tcp => "TCP",
                                crate::pcap::L4Proto::Udp => "UDP",
                                crate::pcap::L4Proto::Other(_) => "L4",
                            };
                            let line = Line::from(vec![
                                Span::styled(format!("{:>3} ", row_i + 1), Style::default().fg(c_muted())),
                                Span::styled(format!("{:<3} ", proto), Style::default().fg(c_accent())),
                                Span::styled(
                                    format!("{:>5} ", fl.total_packets),
                                    Style::default().fg(Color::Rgb(200, 200, 210)),
                                ),
                                Span::styled(
                                    format!("{:>8} ", fl.total_bytes),
                                    Style::default().fg(Color::Rgb(200, 200, 210)),
                                ),
                                Span::raw(format!(
                                    "{}:{} ↔ {}:{}",
                                    fl.key.src, fl.key.src_port, fl.key.dst, fl.key.dst_port
                                )),
                            ]);
                            Some(ListItem::new(line))
                        })
                        .collect();

                    let list = List::new(items)
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title("Flows  (Enter packets, / filter, t/u toggles)")
                                .style(Style::default().bg(c_panel())),
                        )
                        .highlight_style(
                            Style::default()
                                .bg(c_highlight_bg())
                                .fg(c_text())
                                .add_modifier(Modifier::BOLD),
                        )
                        .highlight_symbol("❯ ");

                    f.render_stateful_widget(list, body_chunks[0], &mut flow_state);
                }
                View::Packets => {
                    let Some(fl) = app.selected_flow() else {
                        let p = Paragraph::new("No flow selected")
                            .block(Block::default().borders(Borders::ALL).title("Packets"));
                        f.render_widget(p, body_chunks[0]);
                        return;
                    };

                    let items: Vec<ListItem> = fl
                        .packet_indices
                        .iter()
                        .filter_map(|idx| app.rows.get(*idx))
                        .map(|r| {
                            let dir = match r.flow_dir {
                                Some(FlowDir::AtoB) => "→",
                                Some(FlowDir::BtoA) => "←",
                                None => "·",
                            };
                            let line = Line::from(vec![
                                Span::styled(dir, Style::default().fg(c_accent())),
                                Span::raw(" "),
                                Span::styled(format!("#{:<4} ", r.index), Style::default().fg(c_muted())),
                                Span::styled(format!("{:>4}B ", r.len), Style::default().fg(Color::Rgb(190, 200, 220))),
                                Span::styled(r.summary.clone(), Style::default().fg(c_text())),
                            ]);
                            ListItem::new(line)
                        })
                        .collect();

                    let list = List::new(items).block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title("Packets  (f stream, Esc back)")
                            .style(Style::default().bg(c_panel())),
                    );
                    f.render_widget(list, body_chunks[0]);
                }
                View::Stream => {
                    let Some(fl) = app.selected_flow() else {
                        let p = Paragraph::new("No flow selected")
                            .block(Block::default().borders(Borders::ALL).title("Stream"));
                        f.render_widget(p, body_chunks[0]);
                        return;
                    };

                    let stream: StreamData = build_stream(&app.rows, fl);
                    let (label, bytes) = match app.stream_tab {
                        StreamTab::Combined => {
                            let mut c = stream.a_to_b.clone();
                            c.extend_from_slice(b"\n\n---\n\n");
                            c.extend_from_slice(&stream.b_to_a);
                            ("Combined", c)
                        }
                        StreamTab::AtoB => ("A→B", stream.a_to_b),
                        StreamTab::BtoA => ("B→A", stream.b_to_a),
                    };

                    let text = bytes_to_pretty_text(&bytes);
                    let p = Paragraph::new(text)
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title(format!("Stream: {label}  (Tab switch, ↑/↓ scroll, Esc back)"))
                                .style(Style::default().bg(c_panel())),
                        )
                        .wrap(Wrap { trim: false })
                        .scroll((app.stream_scroll, 0));
                    f.render_widget(p, body_chunks[0]);
                }
            }

            // Details panel (always)
            let detail = if let Some(fl) = app.selected_flow() {
                let a = format!("A→B: {} pkts / {} bytes", fl.a_to_b.packets, fl.a_to_b.bytes);
                let b = format!("B→A: {} pkts / {} bytes", fl.b_to_a.packets, fl.b_to_a.bytes);
                vec![
                    Line::from(vec![Span::styled(
                        fl.label(),
                        Style::default().fg(Color::Rgb(255, 215, 0)).add_modifier(Modifier::BOLD),
                    )]),
                    Line::from(Span::raw("")),
                    Line::from(Span::styled(a, Style::default().fg(c_muted()))),
                    Line::from(Span::styled(b, Style::default().fg(c_muted()))),
                ]
            } else {
                vec![Line::from(Span::styled("No flows decoded.", Style::default().fg(c_muted())))]
            };

            let detail = Paragraph::new(detail)
                .block(Block::default().borders(Borders::ALL).title("Details").style(Style::default().bg(c_panel())));
            f.render_widget(detail, body_chunks[1]);

            let footer_line = if app.filter_mode {
                Line::from(vec![
                    Span::styled("FILTER", Style::default().fg(c_accent()).add_modifier(Modifier::BOLD)),
                    Span::raw("  "),
                    Span::styled("type to filter, Enter apply, Esc cancel, Ctrl+u clear", Style::default().fg(c_muted())),
                ])
            } else {
                match app.view {
                    View::Flows => Line::from(vec![
                        Span::styled("↑/↓", Style::default().fg(Color::Green)),
                        Span::raw(" move  "),
                        Span::styled("Enter", Style::default().fg(Color::Green)),
                        Span::raw(" packets  "),
                        Span::styled("/", Style::default().fg(Color::Green)),
                        Span::raw(" filter  "),
                        Span::styled("t/u", Style::default().fg(Color::Green)),
                        Span::raw(" tcp/udp  "),
                        Span::styled("q", Style::default().fg(Color::Green)),
                        Span::raw(" quit"),
                    ]),
                    View::Packets => Line::from(vec![
                        Span::styled("f", Style::default().fg(Color::Green)),
                        Span::raw(" stream  "),
                        Span::styled("Esc", Style::default().fg(Color::Green)),
                        Span::raw(" back  "),
                        Span::styled("q", Style::default().fg(Color::Green)),
                        Span::raw(" quit"),
                    ]),
                    View::Stream => Line::from(vec![
                        Span::styled("Tab", Style::default().fg(Color::Green)),
                        Span::raw(" switch  "),
                        Span::styled("↑/↓", Style::default().fg(Color::Green)),
                        Span::raw(" scroll  "),
                        Span::styled("Esc", Style::default().fg(Color::Green)),
                        Span::raw(" back  "),
                        Span::styled("q", Style::default().fg(Color::Green)),
                        Span::raw(" quit"),
                    ]),
                }
            };

            let footer = Paragraph::new(footer_line)
                .block(Block::default().borders(Borders::ALL).style(Style::default().bg(c_panel())));
            f.render_widget(footer, chunks[2]);

            // Filter modal
            if app.filter_mode {
                let area = centered_rect(70, 20, size);
                f.render_widget(Clear, area);
                let inner = area.inner(Margin { horizontal: 2, vertical: 1 });

                let block = Block::default()
                    .borders(Borders::ALL)
                    .title("Filter")
                    .style(Style::default().bg(c_panel()).fg(c_text()));
                f.render_widget(block, area);

                let q = if app.filter.query.is_empty() {
                    "(empty)".to_string()
                } else {
                    app.filter.query.clone()
                };
                let text = vec![
                    Line::from(vec![Span::styled("Query: ", Style::default().fg(c_muted())), Span::raw(q)]),
                    Line::from(vec![
                        Span::styled("TCP ", Style::default().fg(c_muted())),
                        Span::styled(
                            if app.filter.show_tcp { "on" } else { "off" },
                            Style::default().fg(if app.filter.show_tcp { Color::Green } else { Color::Red }),
                        ),
                        Span::raw("   "),
                        Span::styled("UDP ", Style::default().fg(c_muted())),
                        Span::styled(
                            if app.filter.show_udp { "on" } else { "off" },
                            Style::default().fg(if app.filter.show_udp { Color::Green } else { Color::Red }),
                        ),
                    ]),
                    Line::from(Span::raw("")),
                    Line::from(Span::styled(
                        "Type to filter by ip/port/proto. Press Enter to apply, Esc to cancel.",
                        Style::default().fg(c_muted()),
                    )),
                ];

                let p = Paragraph::new(text)
                    .wrap(Wrap { trim: true })
                    .style(Style::default().bg(c_panel()).fg(c_text()));
                f.render_widget(p, inner);
            }
        })?;

        // Input
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                if app.filter_mode {
                    match key.code {
                        KeyCode::Esc => {
                            app.exit_filter_mode();
                        }
                        KeyCode::Enter => {
                            app.exit_filter_mode();
                        }
                        KeyCode::Backspace => {
                            app.filter_pop();
                        }
                        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            app.filter_clear();
                        }
                        KeyCode::Char(c) => {
                            if !key.modifiers.contains(KeyModifiers::CONTROL)
                                && !key.modifiers.contains(KeyModifiers::ALT)
                            {
                                app.filter_push(c);
                            }
                        }
                        _ => {}
                    }
                    // sync selection
                    flow_state.select(Some(app.selected_row));
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Char('/') => {
                        if app.view == View::Flows {
                            app.enter_filter_mode();
                        }
                    }
                    KeyCode::Char('t') => {
                        if app.view == View::Flows {
                            app.toggle_tcp();
                            flow_state.select(Some(app.selected_row));
                        }
                    }
                    KeyCode::Char('u') => {
                        if app.view == View::Flows {
                            app.toggle_udp();
                            flow_state.select(Some(app.selected_row));
                        }
                    }
                    KeyCode::Esc => {
                        if app.view != View::Flows {
                            app.back();
                        }
                    }
                    KeyCode::Enter => {
                        if app.view == View::Flows {
                            app.open_packets();
                        }
                    }
                    KeyCode::Char('f') => {
                        if app.view == View::Packets {
                            app.open_stream();
                        }
                    }
                    KeyCode::Tab => {
                        if app.view == View::Stream {
                            app.tab_next();
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        match app.view {
                            View::Flows => {
                                app.move_down();
                                flow_state.select(Some(app.selected_row));
                            }
                            View::Stream => app.scroll_down(),
                            _ => {}
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        match app.view {
                            View::Flows => {
                                app.move_up();
                                flow_state.select(Some(app.selected_row));
                            }
                            View::Stream => app.scroll_up(),
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: ratatui::layout::Rect) -> ratatui::layout::Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
