use crate::flow::{FlowIndex, FlowStats};
use crate::pcap::{FlowDir, PacketRow};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::execute;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::Terminal;
use std::io::{self, Stdout};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Flows,
    Packets,
}

pub struct App {
    pub rows: Vec<PacketRow>,
    pub flows: FlowIndex,
    pub selected_flow: usize,
    pub view: View,
}

impl App {
    pub fn new(rows: Vec<PacketRow>, flows: FlowIndex) -> Self {
        App {
            rows,
            flows,
            selected_flow: 0,
            view: View::Flows,
        }
    }

    fn selected_flow(&self) -> Option<&FlowStats> {
        self.flows.flows.get(self.selected_flow)
    }

    fn flow_next(&mut self) {
        if self.flows.flows.is_empty() {
            self.selected_flow = 0;
            return;
        }
        self.selected_flow = (self.selected_flow + 1).min(self.flows.flows.len() - 1);
    }

    fn flow_prev(&mut self) {
        if self.flows.flows.is_empty() {
            self.selected_flow = 0;
            return;
        }
        self.selected_flow = self.selected_flow.saturating_sub(1);
    }

    fn open_packets(&mut self) {
        self.view = View::Packets;
    }

    fn back(&mut self) {
        self.view = View::Flows;
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

fn run_loop(terminal: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App) -> Result<()> {
    let mut flow_state = ListState::default();
    if !app.flows.flows.is_empty() {
        flow_state.select(Some(app.selected_flow));
    }

    loop {
        terminal.draw(|f| {
            let size = f.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(1), Constraint::Length(2)])
                .split(size);

            let title = match app.view {
                View::Flows => "PCAP Viewer (MVP) — Flows",
                View::Packets => "PCAP Viewer (MVP) — Packets",
            };

            let header = Paragraph::new(Line::from(vec![
                Span::styled("babyshark", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::styled(
                    format!("flows: {}  packets: {}", app.flows.flows.len(), app.rows.len()),
                    Style::default().fg(Color::Gray),
                ),
            ]))
            .block(Block::default().borders(Borders::ALL).title(title));
            f.render_widget(header, chunks[0]);

            let body_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                .split(chunks[1]);

            match app.view {
                View::Flows => {
                    let items: Vec<ListItem> = app
                        .flows
                        .flows
                        .iter()
                        .enumerate()
                        .map(|(i, fl)| {
                            let title = fl.label();
                            let meta = format!(" pkts={} bytes={}", fl.total_packets, fl.total_bytes);
                            let line = Line::from(vec![
                                Span::styled(format!("{:>3} ", i + 1), Style::default().fg(Color::DarkGray)),
                                Span::raw(title),
                                Span::styled(meta, Style::default().fg(Color::Gray)),
                            ]);
                            ListItem::new(line)
                        })
                        .collect();

                    let list = List::new(items)
                        .block(Block::default().borders(Borders::ALL).title("Flows"))
                        .highlight_style(
                            Style::default()
                                .bg(Color::Rgb(30, 30, 50))
                                .fg(Color::White)
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
                                Span::styled(dir, Style::default().fg(Color::Cyan)),
                                Span::raw(" "),
                                Span::styled(format!("#{:<4} ", r.index), Style::default().fg(Color::DarkGray)),
                                Span::styled(format!("len={:<4} ", r.len), Style::default().fg(Color::Gray)),
                                Span::raw(r.summary.clone()),
                            ]);
                            ListItem::new(line)
                        })
                        .collect();

                    let list = List::new(items).block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title("Packets (Esc back)"),
                    );
                    f.render_widget(list, body_chunks[0]);
                }
            }

            // Detail panel
            let detail = if let Some(fl) = app.selected_flow() {
                let a = format!("A→B: {} pkts / {} bytes", fl.a_to_b.packets, fl.a_to_b.bytes);
                let b = format!("B→A: {} pkts / {} bytes", fl.b_to_a.packets, fl.b_to_a.bytes);
                let idxs = if fl.packet_indices.len() <= 12 {
                    format!("{:?}", fl.packet_indices)
                } else {
                    format!(
                        "[{}, …, {}] ({} total)",
                        fl.packet_indices.first().unwrap_or(&0),
                        fl.packet_indices.last().unwrap_or(&0),
                        fl.packet_indices.len()
                    )
                };
                vec![
                    Line::from(vec![Span::styled(
                        fl.label(),
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                    )]),
                    Line::from(Span::raw("")),
                    Line::from(Span::styled(a, Style::default().fg(Color::Gray))),
                    Line::from(Span::styled(b, Style::default().fg(Color::Gray))),
                    Line::from(Span::raw("")),
                    Line::from(vec![
                        Span::styled("Packet indices: ", Style::default().fg(Color::Gray)),
                        Span::raw(idxs),
                    ]),
                ]
            } else {
                vec![Line::from(Span::styled(
                    "No flows decoded.",
                    Style::default().fg(Color::Gray),
                ))]
            };

            let detail = Paragraph::new(detail)
                .block(Block::default().borders(Borders::ALL).title("Details"));
            f.render_widget(detail, body_chunks[1]);

            let footer_line = match app.view {
                View::Flows => Line::from(vec![
                    Span::styled("↑/↓", Style::default().fg(Color::Green)),
                    Span::raw(" move  "),
                    Span::styled("Enter", Style::default().fg(Color::Green)),
                    Span::raw(" packets  "),
                    Span::styled("q", Style::default().fg(Color::Green)),
                    Span::raw(" quit"),
                ]),
                View::Packets => Line::from(vec![
                    Span::styled("Esc", Style::default().fg(Color::Green)),
                    Span::raw(" back  "),
                    Span::styled("q", Style::default().fg(Color::Green)),
                    Span::raw(" quit  "),
                    Span::styled("(next: follow stream)", Style::default().fg(Color::Gray)),
                ]),
            };

            let footer = Paragraph::new(footer_line).block(Block::default().borders(Borders::ALL));
            f.render_widget(footer, chunks[2]);
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Esc => {
                        if app.view == View::Packets {
                            app.back();
                        }
                    }
                    KeyCode::Enter => {
                        if app.view == View::Flows {
                            app.open_packets();
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if app.view == View::Flows {
                            app.flow_next();
                            flow_state.select(Some(app.selected_flow));
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if app.view == View::Flows {
                            app.flow_prev();
                            flow_state.select(Some(app.selected_flow));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}
