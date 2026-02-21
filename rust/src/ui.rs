use crate::casefile::CaseFile;
use crate::flow::{FlowIndex, FlowStats};
use crate::pcap::{FlowDir, PacketRow};
// stream module referenced via `crate::stream::...`
use crate::ui_filter::FlowFilter;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Margin};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Terminal;
use std::io::{self, Stdout};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn build_stream_bytes(rows: &[PacketRow], fl: &FlowStats, tab: StreamTab) -> Vec<u8> {
    let stream = crate::stream::build_stream(rows, fl);
    match tab {
        StreamTab::Combined => {
            let mut c = stream.a_to_b;
            c.extend_from_slice(b"\n\n---\n\n");
            c.extend_from_slice(&stream.b_to_a);
            c
        }
        StreamTab::AtoB => stream.a_to_b,
        StreamTab::BtoA => stream.b_to_a,
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modal {
    None,
    Filter,
    Bookmark,
    StreamSearch,
}

pub struct App {
    pub pcap_path: PathBuf,
    pub casefile: CaseFile,

    pub rows: Vec<PacketRow>,
    pub flows: FlowIndex,

    pub view: View,

    // flows selection is by index into `visible_flow_indices`
    pub selected_row: usize,
    pub visible_flow_indices: Vec<usize>,

    // filter
    pub filter: FlowFilter,

    // bookmark
    pub bookmark_note: String,

    pub modal: Modal,

    // stream view state
    pub stream_tab: StreamTab,
    pub stream_scroll: u16,

    // stream search
    pub stream_search: String,
    pub stream_last_match: Option<usize>,
}

impl App {
    pub fn new(pcap_path: impl AsRef<Path>, rows: Vec<PacketRow>, flows: FlowIndex) -> Self {
        let pcap_path = pcap_path.as_ref().to_path_buf();
        let casefile = CaseFile::load_or_new(&pcap_path).unwrap_or_default();

        let mut app = App {
            pcap_path,
            casefile,
            rows,
            flows,
            view: View::Flows,
            selected_row: 0,
            visible_flow_indices: Vec::new(),
            filter: FlowFilter::default(),
            bookmark_note: String::new(),
            modal: Modal::None,
            stream_tab: StreamTab::Combined,
            stream_scroll: 0,
            stream_search: String::new(),
            stream_last_match: None,
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
        self.stream_last_match = None;
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
        self.stream_last_match = None;
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

    fn open_filter(&mut self) {
        self.modal = Modal::Filter;
    }

    fn open_bookmark(&mut self) {
        self.modal = Modal::Bookmark;
        self.bookmark_note.clear();
    }

    fn open_stream_search(&mut self) {
        self.modal = Modal::StreamSearch;
        self.stream_last_match = None;
        // keep existing search text
    }

    fn close_modal_apply(&mut self) {
        match self.modal {
            Modal::Filter => {
                self.recompute_visible();
            }
            Modal::Bookmark => {
                if let Some(fl) = self.selected_flow() {
                    let key = fl.label();
                    self.casefile
                        .upsert_bookmark(&key, &key, self.bookmark_note.trim());
                    let _ = self.casefile.save(&self.pcap_path);
                }
            }
            Modal::StreamSearch => {
                self.stream_last_match = None;
                if self.view == View::Stream {
                    if let Some(fl) = self.selected_flow() {
                        let bytes = build_stream_bytes(&self.rows, fl, self.stream_tab);
                        let needle = self.stream_search.as_bytes();
                        if !needle.is_empty() {
                            if let Some(pos) = crate::search::find_subslice(&bytes, needle) {
                                self.stream_last_match = Some(pos);
                                self.stream_scroll =
                                    ((pos + (HEXDUMP_COLS - 1)) / HEXDUMP_COLS) as u16;
                            }
                        }
                    }
                }
            }
            Modal::None => {}
        }
        self.modal = Modal::None;
    }

    fn close_modal_cancel(&mut self) {
        self.modal = Modal::None;
    }

    fn modal_push(&mut self, c: char) {
        match self.modal {
            Modal::Filter => {
                self.filter.query.push(c);
                self.recompute_visible();
            }
            Modal::Bookmark => {
                self.bookmark_note.push(c);
            }
            Modal::StreamSearch => {
                self.stream_search.push(c);
            }
            Modal::None => {}
        }
    }

    fn modal_pop(&mut self) {
        match self.modal {
            Modal::Filter => {
                self.filter.query.pop();
                self.recompute_visible();
            }
            Modal::Bookmark => {
                self.bookmark_note.pop();
            }
            Modal::StreamSearch => {
                self.stream_search.pop();
            }
            Modal::None => {}
        }
    }

    fn modal_clear(&mut self) {
        match self.modal {
            Modal::Filter => {
                self.filter.query.clear();
                self.recompute_visible();
            }
            Modal::Bookmark => {
                self.bookmark_note.clear();
            }
            Modal::StreamSearch => {
                self.stream_search.clear();
            }
            Modal::None => {}
        }
    }

    fn export_report(&mut self) -> Result<PathBuf> {
        let dir = crate::casefile::case_dir_for_pcap(&self.pcap_path);
        std::fs::create_dir_all(&dir)?;
        let out = dir.join("report.md");

        let selected = self.selected_flow();
        crate::report::write_report_md(
            &out,
            &self.pcap_path,
            &self.rows,
            &self.flows,
            &self.filter,
            &self.casefile.bookmarks,
            selected,
            crate::report::ReportOptions::default(),
        )
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

fn byte_ascii(b: u8) -> char {
    let c = b as char;
    if c.is_ascii_graphic() || c == ' ' {
        c
    } else {
        '.'
    }
}

fn byte_is_printable(b: u8) -> bool {
    let c = b as char;
    c.is_ascii_graphic() || c == ' '
}

const HEXDUMP_COLS: usize = 16;

fn bytes_to_pretty_lines(bytes: &[u8], highlight: Option<(usize, usize)>) -> Vec<Line<'static>> {
    let mut lines: Vec<Line> = Vec::new();
    let mut offset: usize = 0;

    let (hl_start, hl_end) = highlight
        .map(|(s, len)| (s, s.saturating_add(len)))
        .unwrap_or((usize::MAX, usize::MAX));

    while offset < bytes.len() {
        let chunk = &bytes[offset..bytes.len().min(offset + HEXDUMP_COLS)];

        let mut spans: Vec<Span> = Vec::new();
        spans.push(Span::styled(
            format!("{:08x}  ", offset),
            Style::default().fg(c_muted()),
        ));

        // hex bytes with spacing and a mid-group separator for readability
        for i in 0..HEXDUMP_COLS {
            if i == (HEXDUMP_COLS / 2) {
                spans.push(Span::raw("  "));
            } else if i != 0 {
                spans.push(Span::raw(" "));
            }

            if i < chunk.len() {
                let abs = offset + i;
                let in_hl = abs >= hl_start && abs < hl_end;
                let st = if in_hl {
                    Style::default().fg(c_bg()).bg(c_accent()).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(c_muted())
                };
                spans.push(Span::styled(format!("{:02x}", chunk[i]), st));
            } else {
                spans.push(Span::styled("  ", Style::default().fg(c_muted())));
            }
        }

        spans.push(Span::raw("  |"));
        spans.push(Span::styled(" ", Style::default().fg(c_muted())));

        // ascii
        for i in 0..HEXDUMP_COLS {
            if i < chunk.len() {
                let abs = offset + i;
                let in_hl = abs >= hl_start && abs < hl_end;
                let st = if in_hl {
                    Style::default().fg(c_bg()).bg(c_accent()).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(if byte_is_printable(chunk[i]) {
                        c_text()
                    } else {
                        c_muted()
                    })
                };
                spans.push(Span::styled(byte_ascii(chunk[i]).to_string(), st));
            } else {
                spans.push(Span::raw(" "));
            }
        }

        spans.push(Span::raw("|"));

        lines.push(Line::from(spans));
        offset += HEXDUMP_COLS;
    }

    lines
}

fn bytes_to_pretty_text(bytes: &[u8], highlight: Option<(usize, usize)>) -> Text<'static> {
    Text::from(bytes_to_pretty_lines(bytes, highlight))
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
                Span::styled(
                    "babyshark",
                    Style::default().fg(c_accent()).add_modifier(Modifier::BOLD),
                ),
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
                                .title("Flows  (Enter packets, / filter, t/u toggles, b bookmark, E export)")
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
                                Span::styled(
                                    format!("{:>4}B ", r.len),
                                    Style::default().fg(Color::Rgb(190, 200, 220)),
                                ),
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

                    let (label, bytes) = match app.stream_tab {
                        StreamTab::Combined => ("Combined", build_stream_bytes(&app.rows, fl, app.stream_tab)),
                        StreamTab::AtoB => ("A→B", build_stream_bytes(&app.rows, fl, app.stream_tab)),
                        StreamTab::BtoA => ("B→A", build_stream_bytes(&app.rows, fl, app.stream_tab)),
                    };

                    let highlight = app
                        .stream_last_match
                        .map(|pos| (pos, app.stream_search.as_bytes().len()));
                    let text = bytes_to_pretty_text(&bytes, highlight);
                    let p = Paragraph::new(text)
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title(format!("Stream: {label}  (Tab switch, / search, n/N next/prev, ↑/↓ scroll, Esc back)"))
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
                let bookmarks = app.casefile.bookmarks.len();
                vec![
                    Line::from(vec![Span::styled(
                        fl.label(),
                        Style::default().fg(Color::Rgb(255, 215, 0)).add_modifier(Modifier::BOLD),
                    )]),
                    Line::from(Span::raw("")),
                    Line::from(Span::styled(a, Style::default().fg(c_muted()))),
                    Line::from(Span::styled(b, Style::default().fg(c_muted()))),
                    Line::from(Span::raw("")),
                    Line::from(vec![
                        Span::styled("bookmarks: ", Style::default().fg(c_muted())),
                        Span::raw(format!("{bookmarks}")),
                    ]),
                ]
            } else {
                vec![Line::from(Span::styled("No flows decoded.", Style::default().fg(c_muted())))]
            };

            let detail = Paragraph::new(detail).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Details")
                    .style(Style::default().bg(c_panel())),
            );
            f.render_widget(detail, body_chunks[1]);

            let footer_line = match app.modal {
                Modal::Filter => Line::from(vec![
                    Span::styled("FILTER", Style::default().fg(c_accent()).add_modifier(Modifier::BOLD)),
                    Span::raw("  "),
                    Span::styled("type, Enter apply, Esc cancel, Ctrl+u clear", Style::default().fg(c_muted())),
                ]),
                Modal::Bookmark => Line::from(vec![
                    Span::styled("BOOKMARK", Style::default().fg(c_accent()).add_modifier(Modifier::BOLD)),
                    Span::raw("  "),
                    Span::styled("type note, Enter save, Esc cancel, Ctrl+u clear", Style::default().fg(c_muted())),
                ]),
                Modal::StreamSearch => Line::from(vec![
                    Span::styled("SEARCH", Style::default().fg(c_accent()).add_modifier(Modifier::BOLD)),
                    Span::raw("  "),
                    Span::styled("type query, Enter apply, Esc cancel, Ctrl+u clear", Style::default().fg(c_muted())),
                ]),
                Modal::None => match app.view {
                    View::Flows => Line::from(vec![
                        Span::styled("↑/↓", Style::default().fg(Color::Green)),
                        Span::raw(" move  "),
                        Span::styled("Enter", Style::default().fg(Color::Green)),
                        Span::raw(" packets  "),
                        Span::styled("/", Style::default().fg(Color::Green)),
                        Span::raw(" filter  "),
                        Span::styled("t/u", Style::default().fg(Color::Green)),
                        Span::raw(" tcp/udp  "),
                        Span::styled("b", Style::default().fg(Color::Green)),
                        Span::raw(" bookmark  "),
                        Span::styled("E", Style::default().fg(Color::Green)),
                        Span::raw(" export  "),
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
                        Span::styled("/", Style::default().fg(Color::Green)),
                        Span::raw(" search  "),
                        Span::styled("n/N", Style::default().fg(Color::Green)),
                        Span::raw(" next/prev  "),
                        Span::styled("Tab", Style::default().fg(Color::Green)),
                        Span::raw(" switch  "),
                        Span::styled("↑/↓", Style::default().fg(Color::Green)),
                        Span::raw(" scroll  "),
                        Span::styled("Esc", Style::default().fg(Color::Green)),
                        Span::raw(" back  "),
                        Span::styled("q", Style::default().fg(Color::Green)),
                        Span::raw(" quit"),
                    ]),
                },
            };

            let footer = Paragraph::new(footer_line)
                .block(Block::default().borders(Borders::ALL).style(Style::default().bg(c_panel())));
            f.render_widget(footer, chunks[2]);

            // Modal
            match app.modal {
                Modal::Filter => {
                    render_modal(f, size, "Filter", &app.filter.query, app.filter.show_tcp, app.filter.show_udp);
                }
                Modal::Bookmark => {
                    render_modal(f, size, "Bookmark note", &app.bookmark_note, app.filter.show_tcp, app.filter.show_udp);
                }
                Modal::StreamSearch => {
                    render_search_modal(f, size, &app.stream_search, app.stream_last_match.is_some());
                }
                Modal::None => {}
            }
        })?;

        // Input
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                if app.modal != Modal::None {
                    match key.code {
                        KeyCode::Esc => app.close_modal_cancel(),
                        KeyCode::Enter => app.close_modal_apply(),
                        KeyCode::Backspace => app.modal_pop(),
                        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            app.modal_clear();
                        }
                        KeyCode::Char(c) => {
                            if !key.modifiers.contains(KeyModifiers::CONTROL)
                                && !key.modifiers.contains(KeyModifiers::ALT)
                            {
                                app.modal_push(c);
                            }
                        }
                        _ => {}
                    }
                    flow_state.select(Some(app.selected_row));
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Char('/') => {
                        if app.view == View::Flows {
                            app.open_filter();
                        } else if app.view == View::Stream {
                            app.open_stream_search();
                        }
                    }
                    KeyCode::Char('n') => {
                        if app.view == View::Stream {
                            let needle = app.stream_search.as_bytes();
                            if !needle.is_empty() {
                                if let Some(fl) = app.selected_flow() {
                                    let bytes = build_stream_bytes(&app.rows, fl, app.stream_tab);
                                    let start = app
                                        .stream_last_match
                                        .map(|p| p + needle.len())
                                        .unwrap_or(0);
                                    let pos = crate::search::find_next_subslice_from(
                                        &bytes, needle, start,
                                    )
                                    .or_else(|| {
                                        crate::search::find_next_subslice_from(&bytes, needle, 0)
                                    });
                                    if let Some(pos) = pos {
                                        app.stream_last_match = Some(pos);
                                        app.stream_scroll =
                                            ((pos + (HEXDUMP_COLS - 1)) / HEXDUMP_COLS) as u16;
                                    }
                                }
                            }
                        }
                    }
                    KeyCode::Char('N') => {
                        if app.view == View::Stream {
                            let needle = app.stream_search.as_bytes();
                            if !needle.is_empty() {
                                if let Some(fl) = app.selected_flow() {
                                    let bytes = build_stream_bytes(&app.rows, fl, app.stream_tab);
                                    let before = app
                                        .stream_last_match
                                        .unwrap_or(bytes.len())
                                        .saturating_sub(1);
                                    let pos = crate::search::find_prev_subslice_before(
                                        &bytes, needle, before,
                                    )
                                    .or_else(|| {
                                        crate::search::find_prev_subslice_before(
                                            &bytes,
                                            needle,
                                            bytes.len(),
                                        )
                                    });
                                    if let Some(pos) = pos {
                                        app.stream_last_match = Some(pos);
                                        app.stream_scroll =
                                            ((pos + (HEXDUMP_COLS - 1)) / HEXDUMP_COLS) as u16;
                                    }
                                }
                            }
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
                    KeyCode::Char('b') => {
                        if app.view == View::Flows {
                            app.open_bookmark();
                        }
                    }
                    KeyCode::Char('E') => {
                        if app.view == View::Flows {
                            let _ = app.export_report();
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
                    KeyCode::Down | KeyCode::Char('j') => match app.view {
                        View::Flows => {
                            app.move_down();
                            flow_state.select(Some(app.selected_row));
                        }
                        View::Stream => app.scroll_down(),
                        _ => {}
                    },
                    KeyCode::Up | KeyCode::Char('k') => match app.view {
                        View::Flows => {
                            app.move_up();
                            flow_state.select(Some(app.selected_row));
                        }
                        View::Stream => app.scroll_up(),
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
    }
}

fn centered_rect(
    percent_x: u16,
    percent_y: u16,
    r: ratatui::layout::Rect,
) -> ratatui::layout::Rect {
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

fn render_modal(
    f: &mut ratatui::Frame,
    size: ratatui::layout::Rect,
    title: &str,
    input: &str,
    show_tcp: bool,
    show_udp: bool,
) {
    let area = centered_rect(70, 22, size);
    f.render_widget(Clear, area);
    let inner = area.inner(Margin {
        horizontal: 2,
        vertical: 1,
    });

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .style(Style::default().bg(c_panel()).fg(c_text()));
    f.render_widget(block, area);

    let q = if input.is_empty() { "(empty)" } else { input };

    let mut lines = vec![Line::from(vec![
        Span::styled("Input: ", Style::default().fg(c_muted())),
        Span::raw(q.to_string()),
    ])];

    // For filter modal, show toggles in content; harmless for bookmark modal.
    lines.push(Line::from(vec![
        Span::styled("TCP ", Style::default().fg(c_muted())),
        Span::styled(
            if show_tcp { "on" } else { "off" },
            Style::default().fg(if show_tcp { Color::Green } else { Color::Red }),
        ),
        Span::raw("   "),
        Span::styled("UDP ", Style::default().fg(c_muted())),
        Span::styled(
            if show_udp { "on" } else { "off" },
            Style::default().fg(if show_udp { Color::Green } else { Color::Red }),
        ),
    ]));

    lines.push(Line::from(Span::raw("")));
    lines.push(Line::from(Span::styled(
        "Enter = apply/save   Esc = cancel   Ctrl+u = clear",
        Style::default().fg(c_muted()),
    )));

    let p = Paragraph::new(lines)
        .wrap(Wrap { trim: true })
        .style(Style::default().bg(c_panel()).fg(c_text()));
    f.render_widget(p, inner);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hexdump_highlights_current_match() {
        let bytes = b"abcd";
        let lines = bytes_to_pretty_lines(bytes, Some((1, 2)));
        assert_eq!(lines.len(), 1);

        let want = Style::default().fg(c_bg()).bg(c_accent()).add_modifier(Modifier::BOLD);

        // hex: "62" for 'b' should be highlighted
        let spans = &lines[0].spans;
        let hex_b = spans.iter().find(|s| s.content.as_ref() == "62").unwrap();
        assert_eq!(hex_b.style, want);

        // ascii: "b" should be highlighted
        let ascii_b = spans.iter().find(|s| s.content.as_ref() == "b").unwrap();
        assert_eq!(ascii_b.style, want);

        // hex: "61" for 'a' should not be highlighted
        let hex_a = spans.iter().find(|s| s.content.as_ref() == "61").unwrap();
        assert_ne!(hex_a.style, want);
    }
}

fn render_search_modal(
    f: &mut ratatui::Frame,
    size: ratatui::layout::Rect,
    input: &str,
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
        .title("Stream search")
        .style(Style::default().bg(c_panel()).fg(c_text()));
    f.render_widget(block, area);

    let q = if input.is_empty() { "(empty)" } else { input };

    let status = if input.is_empty() {
        "type to search"
    } else if has_match {
        "match found (n/N to navigate)"
    } else {
        "no matches"
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
                Style::default().fg(if has_match { Color::Green } else { Color::Red }),
            ),
        ]),
        Line::from(Span::raw("")),
        Line::from(Span::styled(
            "Enter = apply   Esc = cancel   Ctrl+u = clear",
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
