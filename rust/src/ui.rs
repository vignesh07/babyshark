use crate::casefile::CaseFile;
use crate::flow::{FlowIndex, FlowStats};
use crate::pcap::{FlowDir, PacketRow};
use chrono::Local;
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
    pub stream_match_count: usize,
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
            stream_tab: StreamTab::AtoB,
            stream_scroll: 0,
            stream_search: String::new(),
            stream_last_match: None,
            stream_match_count: 0,
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
        self.stream_match_count = 0;
    }

    fn back(&mut self) {
        self.view = match self.view {
            View::Flows => View::Flows,
            View::Packets => View::Flows,
            View::Stream => View::Packets,
        };
        self.stream_scroll = 0;
    }

    fn count_stream_matches(&self, bytes: &[u8]) -> usize {
        let needle = self.stream_search.as_bytes();
        if needle.is_empty() {
            0
        } else {
            crate::search::find_all_subslice_positions(bytes, needle, STREAM_MATCH_HIGHLIGHT_CAP)
                .len()
        }
    }

    fn tab_next(&mut self) {
        self.stream_tab = match self.stream_tab {
            StreamTab::Combined => StreamTab::AtoB,
            StreamTab::AtoB => StreamTab::BtoA,
            StreamTab::BtoA => StreamTab::Combined,
        };
        self.stream_scroll = 0;

        // Preserve search context when switching tabs: if we have a query,
        // jump to the first match in the new stream view.
        if self.view == View::Stream {
            if let Some(fl) = self.selected_flow() {
                let bytes = build_stream_bytes(&self.rows, fl, self.stream_tab);
                let needle = self.stream_search.as_bytes();

                self.stream_match_count = self.count_stream_matches(&bytes);

                if let Some((pos, scroll)) = first_match_and_scroll(&bytes, needle) {
                    self.stream_last_match = Some(pos);
                    self.stream_scroll = scroll;
                }
            }
        } else {
            self.stream_last_match = None;
            self.stream_match_count = 0;
        }
    }

    fn tab_prev(&mut self) {
        self.stream_tab = match self.stream_tab {
            StreamTab::Combined => StreamTab::BtoA,
            StreamTab::AtoB => StreamTab::Combined,
            StreamTab::BtoA => StreamTab::AtoB,
        };
        self.stream_scroll = 0;

        // Preserve search context when switching tabs.
        if self.view == View::Stream {
            if let Some(fl) = self.selected_flow() {
                let bytes = build_stream_bytes(&self.rows, fl, self.stream_tab);
                let needle = self.stream_search.as_bytes();

                self.stream_match_count = self.count_stream_matches(&bytes);

                if let Some((pos, scroll)) = first_match_and_scroll(&bytes, needle) {
                    self.stream_last_match = Some(pos);
                    self.stream_scroll = scroll;
                }
            }
        } else {
            self.stream_last_match = None;
            self.stream_match_count = 0;
        }
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
        self.stream_match_count = 0;
        // Reset scroll so search starts from a predictable top-of-stream position.
        self.stream_scroll = 0;

        if self.view == View::Stream {
            if let Some(fl) = self.selected_flow() {
                let bytes = build_stream_bytes(&self.rows, fl, self.stream_tab);
                self.stream_match_count = self.count_stream_matches(&bytes);
            }
        }

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
                self.stream_match_count = 0;

                if self.view == View::Stream {
                    if let Some(fl) = self.selected_flow() {
                        let bytes = build_stream_bytes(&self.rows, fl, self.stream_tab);
                        let needle = self.stream_search.as_bytes();

                        self.stream_match_count = self.count_stream_matches(&bytes);

                        if let Some((pos, scroll)) = first_match_and_scroll(&bytes, needle) {
                            self.stream_last_match = Some(pos);
                            self.stream_scroll = scroll;
                        }
                    }
                }
            }
            Modal::None => {}
        }
        self.modal = Modal::None;
    }

    fn close_modal_cancel(&mut self) {
        if self.modal == Modal::StreamSearch {
            self.stream_last_match = None;
            self.stream_match_count = 0;
            self.stream_scroll = 0;
        }
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
                self.stream_last_match = None;
                self.stream_scroll = 0;

                if self.view == View::Stream {
                    if let Some(fl) = self.selected_flow() {
                        let bytes = build_stream_bytes(&self.rows, fl, self.stream_tab);
                        self.stream_match_count = self.count_stream_matches(&bytes);
                    }
                }
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
                self.stream_last_match = None;
                self.stream_scroll = 0;

                if self.view == View::Stream {
                    if let Some(fl) = self.selected_flow() {
                        let bytes = build_stream_bytes(&self.rows, fl, self.stream_tab);
                        self.stream_match_count = self.count_stream_matches(&bytes);
                    }
                }
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
                self.stream_last_match = None;
                self.stream_match_count = 0;
                self.stream_scroll = 0;
            }
            Modal::None => {}
        }
    }
    fn export_report(&mut self) -> Result<PathBuf> {
        let dir = crate::casefile::case_dir_for_pcap(&self.pcap_path);
        std::fs::create_dir_all(&dir)?;

        let out_latest = dir.join("report.md");
        let ts = Local::now().format("%Y%m%d-%H%M%S").to_string();
        let out_versioned = dir.join(format!("report-{ts}.md"));

        let selected = self.selected_flow();

        // Write latest
        crate::report::write_report_md(
            &out_latest,
            &self.pcap_path,
            &self.rows,
            &self.flows,
            &self.filter,
            &self.casefile.bookmarks,
            selected,
            crate::report::ReportOptions::default(),
        )?;

        // Write versioned
        crate::report::write_report_md(
            &out_versioned,
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

/// Build a fixed 256-entry lookup table indexed by `u8`.
///
/// Used to avoid per-byte allocations while rendering hexdumps.
fn init_u8_lut<F>(mut f: F) -> Box<[Box<str>]>
where
    F: FnMut(u8) -> Box<str>,
{
    (0u16..=255)
        .map(|i| f(i as u8))
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

fn ascii_cell(b: u8) -> &'static str {
    use std::sync::OnceLock;

    static LUT: OnceLock<Box<[Box<str>]>> = OnceLock::new();
    let lut = LUT.get_or_init(|| {
        init_u8_lut(|b| match b {
            b'\n' => "⏎".to_string().into_boxed_str(),
            b'\t' => "⇥".to_string().into_boxed_str(),
            _ => {
                let c = b as char;
                if c.is_ascii_graphic() || c == ' ' {
                    c.to_string().into_boxed_str()
                } else {
                    ".".to_string().into_boxed_str()
                }
            }
        })
    });

    &lut[b as usize]
}

fn byte_is_printable(b: u8) -> bool {
    matches!(b, b'\n' | b'\t') || {
        let c = b as char;
        c.is_ascii_graphic() || c == ' '
    }
}

const HEXDUMP_OFFSET_LUT_MAX: usize = 0xFFFF;
// Placeholder shown when the offset exceeds the cached LUT range.
// (Fixed width to preserve column alignment.)
const HEXDUMP_OFFSET_TOO_LARGE: &str = "0x??????  ";

/// Format a hexdump offset as an owned string.
///
/// Used for lookup table initialization.
fn fmt_hexdump_offset_owned(offset: usize) -> Box<str> {
    format!("0x{:>6x}  ", offset).into_boxed_str()
}

/// Format a hexdump offset for display.
///
/// Fast path: cached strings for offsets up to `HEXDUMP_OFFSET_LUT_MAX`.
fn fmt_hexdump_offset(offset: usize) -> &'static str {
    use std::sync::OnceLock;

    // Precompute offsets for 0..=0xFFFF (more than enough for typical small captures).
    // If we ever exceed this, fall back to a formatted string.

    static LUT: OnceLock<Box<[Box<str>]>> = OnceLock::new();
    let lut = LUT.get_or_init(|| {
        (0..=HEXDUMP_OFFSET_LUT_MAX)
            .map(|i| fmt_hexdump_offset_owned(i))
            .collect::<Vec<_>>()
            .into_boxed_slice()
    });

    if offset <= HEXDUMP_OFFSET_LUT_MAX {
        &lut[offset]
    } else {
        // Should be very rare; we keep a placeholder rather than leaking.
        HEXDUMP_OFFSET_TOO_LARGE
    }
}

fn hex_byte_upper(b: u8) -> &'static str {
    use std::sync::OnceLock;

    static LUT: OnceLock<Box<[Box<str>]>> = OnceLock::new();
    let lut = LUT.get_or_init(|| init_u8_lut(|b| format!("{:02X}", b).into_boxed_str()));
    &lut[b as usize]
}

const HEXDUMP_COLS: usize = 16;
const HEXDUMP_GROUP: usize = HEXDUMP_COLS / 2;
const HEXDUMP_GUTTER: &str = "  | ";
const HEXDUMP_GUTTER_END: &str = " |";
const HEXDUMP_SPLIT: &str = "  ";
// Heuristic: roughly enough spans for offset + hex bytes + separators + ascii + end gutter.
const HEXDUMP_SPANS_CAP: usize = 8 + HEXDUMP_COLS * 4;
// Single space used in various UI renderings (including hexdump byte separators).
const UI_ONE_SPACE: &str = " ";
const UI_SPACER: &str = "  ";
const STREAM_MATCH_HIGHLIGHT_CAP: usize = 2000;

fn match_cap_suffix(total: usize) -> &'static str {
    if total >= STREAM_MATCH_HIGHLIGHT_CAP {
        "+"
    } else {
        ""
    }
}

fn match_ordinal(match_positions: &[usize], current: Option<usize>) -> Option<usize> {
    let cur = current?;
    match_positions.iter().position(|p| *p == cur)
}

fn scroll_for_match_pos(pos: usize) -> u16 {
    (pos / HEXDUMP_COLS) as u16
}

fn byte_in_any_range(abs: usize, ranges: &[(usize, usize)]) -> bool {
    ranges
        .binary_search_by(|(s, e)| {
            if abs < *s {
                std::cmp::Ordering::Greater
            } else if abs >= *e {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

fn style_current_match() -> Style {
    Style::default()
        .fg(Color::Black)
        .bg(c_accent())
        .add_modifier(Modifier::BOLD)
}

fn style_any_match_base() -> Style {
    Style::default().fg(Color::Black).bg(c_accent())
}

fn style_any_match() -> Style {
    style_any_match_base().add_modifier(Modifier::DIM)
}

fn first_match_and_scroll(bytes: &[u8], needle: &[u8]) -> Option<(usize, u16)> {
    if needle.is_empty() {
        return None;
    }
    let pos = crate::search::find_subslice(bytes, needle)?;
    let scroll = scroll_for_match_pos(pos);
    Some((pos, scroll))
}

fn next_match_and_scroll(
    bytes: &[u8],
    needle: &[u8],
    last_match: Option<usize>,
) -> Option<(usize, u16)> {
    if needle.is_empty() {
        return None;
    }

    let start = last_match.map(|p| p + needle.len()).unwrap_or(0);
    let pos = crate::search::find_next_subslice_from(bytes, needle, start)
        .or_else(|| crate::search::find_next_subslice_from(bytes, needle, 0))?;

    let scroll = scroll_for_match_pos(pos);
    Some((pos, scroll))
}

fn prev_match_and_scroll(
    bytes: &[u8],
    needle: &[u8],
    last_match: Option<usize>,
) -> Option<(usize, u16)> {
    if needle.is_empty() {
        return None;
    }

    let before = last_match.unwrap_or(bytes.len()).saturating_sub(1);
    let pos = crate::search::find_prev_subslice_before(bytes, needle, before)
        .or_else(|| crate::search::find_prev_subslice_before(bytes, needle, bytes.len()))?;

    let scroll = scroll_for_match_pos(pos);
    Some((pos, scroll))
}

fn bytes_to_pretty_lines(
    bytes: &[u8],
    match_ranges: &[(usize, usize)],
    current_match: Option<(usize, usize)>,
) -> Vec<Line<'static>> {
    let mut lines: Vec<Line> = Vec::with_capacity((bytes.len() + HEXDUMP_COLS - 1) / HEXDUMP_COLS);
    let mut offset: usize = 0;

    let (cur_start, cur_end) = current_match
        .map(|(s, len)| (s, s.saturating_add(len)))
        .unwrap_or((usize::MAX, usize::MAX));

    while offset < bytes.len() {
        let chunk = &bytes[offset..bytes.len().min(offset + HEXDUMP_COLS)];

        let mut spans: Vec<Span> = Vec::with_capacity(HEXDUMP_SPANS_CAP);
        spans.push(Span::styled(
            fmt_hexdump_offset(offset),
            Style::default().fg(c_muted()).add_modifier(Modifier::DIM),
        ));

        // hex bytes with spacing and a mid-group separator for readability
        for i in 0..HEXDUMP_COLS {
            if i == HEXDUMP_GROUP {
                spans.push(Span::raw(HEXDUMP_SPLIT));
            } else if i != 0 {
                spans.push(Span::raw(UI_ONE_SPACE));
            }

            if i < chunk.len() {
                let abs = offset + i;
                let in_cur = abs >= cur_start && abs < cur_end;
                let in_any = byte_in_any_range(abs, match_ranges);

                let st = if in_cur {
                    style_current_match()
                } else if in_any {
                    style_any_match()
                } else {
                    Style::default().fg(c_muted())
                };

                spans.push(Span::styled(hex_byte_upper(chunk[i]), st));
            } else {
                spans.push(Span::styled(
                    "  ",
                    Style::default().fg(c_muted()).add_modifier(Modifier::DIM),
                ));
            }
        }

        spans.push(Span::styled(
            HEXDUMP_GUTTER,
            Style::default().fg(c_muted()).add_modifier(Modifier::DIM),
        ));

        // ascii
        for i in 0..HEXDUMP_COLS {
            if i < chunk.len() {
                let abs = offset + i;
                let in_cur = abs >= cur_start && abs < cur_end;
                let in_any = byte_in_any_range(abs, match_ranges);

                let st = if in_cur {
                    style_current_match()
                } else if in_any {
                    style_any_match()
                } else {
                    Style::default().fg(if byte_is_printable(chunk[i]) {
                        c_text()
                    } else {
                        c_muted()
                    })
                };
                spans.push(Span::styled(ascii_cell(chunk[i]), st));
            } else {
                spans.push(Span::raw(UI_ONE_SPACE));
            }
        }

        spans.push(Span::styled(
            HEXDUMP_GUTTER_END,
            Style::default().fg(c_muted()).add_modifier(Modifier::DIM),
        ));

        lines.push(Line::from(spans));
        offset += HEXDUMP_COLS;
    }

    lines
}

fn bytes_to_pretty_text(
    bytes: &[u8],
    match_ranges: &[(usize, usize)],
    current_match: Option<(usize, usize)>,
) -> Text<'static> {
    Text::from(bytes_to_pretty_lines(bytes, match_ranges, current_match))
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
                Span::raw(UI_SPACER),
                Span::styled(title, Style::default().fg(c_text()).add_modifier(Modifier::BOLD)),
                Span::raw(UI_SPACER),
                Span::styled(
                    format!("flows:{} packets:{}", app.visible_flow_indices.len(), app.rows.len()),
                    Style::default().fg(c_muted()),
                ),
                Span::raw(UI_SPACER),
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
                                Span::raw(UI_ONE_SPACE),
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

                    let needle = app.stream_search.as_bytes();
                    let match_positions: Vec<usize> = if needle.is_empty() {
                        Vec::new()
                    } else {
                        crate::search::find_all_subslice_positions(&bytes, needle, STREAM_MATCH_HIGHLIGHT_CAP)
                    };
                    app.stream_match_count = match_positions.len();
                    let match_ranges: Vec<(usize, usize)> = match_positions
                        .iter()
                        .map(|pos| (*pos, pos.saturating_add(needle.len())))
                        .collect();

                    let current = app.stream_last_match.map(|pos| (pos, needle.len()));

                    let status = if needle.is_empty() {
                        String::new()
                    } else {
                        let total = app.stream_match_count;
                        if total == 0 {
                            format!("  search=\"{}\" (0 matches)", app.stream_search)
                        } else {
                            let cur = match_ordinal(&match_positions, app.stream_last_match)
                                .map(|i| i + 1)
                                .unwrap_or(0);
                            let cur_disp = cur.max(1);
                            format!(
                                "  search=\"{}\" {cur_disp}/{total}{}",
                                app.stream_search,
                                match_cap_suffix(total),
                            )
                        }
                    };

                    let title = format!(
                        "Stream: {label}{status}  (Tab/Shift-Tab A→B/B→A/Combined, / search (Enter apply), n/N next/prev, ↑/↓ scroll, Esc back/clear)"
                    );

                    let text = bytes_to_pretty_text(&bytes, &match_ranges, current);
                    let p = Paragraph::new(text)
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title(title)
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
                    Span::raw(UI_SPACER),
                    Span::styled("type, Enter apply, Esc cancel, Ctrl+u clear", Style::default().fg(c_muted())),
                ]),
                Modal::Bookmark => Line::from(vec![
                    Span::styled("BOOKMARK", Style::default().fg(c_accent()).add_modifier(Modifier::BOLD)),
                    Span::raw(UI_SPACER),
                    Span::styled("type note, Enter save, Esc cancel, Ctrl+u clear", Style::default().fg(c_muted())),
                ]),
                Modal::StreamSearch => Line::from(vec![
                    Span::styled("SEARCH", Style::default().fg(c_accent()).add_modifier(Modifier::BOLD)),
                    Span::raw(UI_SPACER),
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
                        Span::raw(" back/clear  "),
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
                        Span::raw(" back/clear  "),
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
                    render_search_modal(
                        f,
                        size,
                        &app.stream_search,
                        app.stream_match_count,
                        app.stream_last_match.is_some(),
                    );
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
                            if let Some(fl) = app.selected_flow() {
                                let bytes = build_stream_bytes(&app.rows, fl, app.stream_tab);
                                if let Some((pos, scroll)) =
                                    next_match_and_scroll(&bytes, needle, app.stream_last_match)
                                {
                                    app.stream_last_match = Some(pos);
                                    app.stream_scroll = scroll;
                                }
                            }
                        }
                    }
                    KeyCode::Char('N') => {
                        if app.view == View::Stream {
                            let needle = app.stream_search.as_bytes();
                            if let Some(fl) = app.selected_flow() {
                                let bytes = build_stream_bytes(&app.rows, fl, app.stream_tab);
                                if let Some((pos, scroll)) =
                                    prev_match_and_scroll(&bytes, needle, app.stream_last_match)
                                {
                                    app.stream_last_match = Some(pos);
                                    app.stream_scroll = scroll;
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
                    KeyCode::BackTab => {
                        if app.view == View::Stream {
                            app.tab_prev();
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => match app.view {
                        View::Flows => {
                            app.move_down();
                            flow_state.select(Some(app.selected_row));
                        }
                        View::Stream => {
                            app.scroll_down();
                        }
                        _ => {}
                    },
                    KeyCode::Up | KeyCode::Char('k') => match app.view {
                        View::Flows => {
                            app.move_up();
                            flow_state.select(Some(app.selected_row));
                        }
                        View::Stream => {
                            app.scroll_up();
                        }
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
        let lines = bytes_to_pretty_lines(bytes, &[], Some((1, 2)));
        assert_eq!(lines.len(), 1);

        let want = Style::default()
            .fg(Color::Black)
            .bg(c_accent())
            .add_modifier(Modifier::BOLD);

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

    #[test]
    fn hexdump_uses_space_padding_for_short_final_line() {
        let bytes = b"a";
        let lines = bytes_to_pretty_lines(bytes, &[], None);
        assert_eq!(lines.len(), 1);

        // We intentionally render missing bytes as two spaces (not "..")
        // so the ASCII column stays aligned and the output looks like a classic hexdump.
        let spans = &lines[0].spans;
        assert!(spans.iter().any(|s| s.content.as_ref() == "  "));
        assert!(!spans.iter().any(|s| s.content.as_ref() == ".."));
    }

    #[test]
    fn hexdump_highlights_all_matches_and_distinguishes_current() {
        let bytes = b"abxxab";

        // Both occurrences of "ab" should be highlighted; the first is the current match.
        let ranges = vec![(0usize, 2usize), (4usize, 6usize)];
        let lines = bytes_to_pretty_lines(bytes, &ranges, Some((0, 2)));
        assert_eq!(lines.len(), 1);

        let current_style = Style::default()
            .fg(Color::Black)
            .bg(c_accent())
            .add_modifier(Modifier::BOLD);
        let any_style = style_any_match();

        let spans = &lines[0].spans;

        // There are two '61' (hex for 'a') spans, one per occurrence.
        let a_hex: Vec<_> = spans
            .iter()
            .filter(|s| s.content.as_ref() == "61")
            .collect();
        assert_eq!(a_hex.len(), 2);
        assert_eq!(a_hex[0].style, current_style);
        assert_eq!(a_hex[1].style, any_style);

        // ASCII 'a' also appears twice and should follow the same styles.
        let a_ascii: Vec<_> = spans.iter().filter(|s| s.content.as_ref() == "a").collect();
        assert_eq!(a_ascii.len(), 2);
        assert_eq!(a_ascii[0].style, current_style);
        assert_eq!(a_ascii[1].style, any_style);
    }

    #[test]
    fn stream_next_prev_match_helpers_wrap_and_compute_scroll() {
        let bytes = b"abxxab";
        let needle = b"ab";

        // next from the last match wraps back to the first
        let (pos, scroll) = next_match_and_scroll(bytes, needle, Some(4)).unwrap();
        assert_eq!(pos, 0);
        assert_eq!(scroll, 0);

        // prev from the first match wraps to the last
        let (pos, scroll) = prev_match_and_scroll(bytes, needle, Some(0)).unwrap();
        assert_eq!(pos, 4);
        assert_eq!(scroll, 0);

        // Scroll computation: match at offset 32 should land on row 2 (0-indexed) with 16 columns.
        let mut big = vec![b'x'; 40];
        big[32] = b'a';
        big[33] = b'b';
        let (pos, scroll) = first_match_and_scroll(&big, needle).unwrap();
        assert_eq!(pos, 32);
        assert_eq!(scroll, 2);
    }

    #[test]
    fn match_ordinal_finds_current_match_index() {
        let positions = vec![0usize, 4usize, 10usize];
        assert_eq!(match_ordinal(&positions, Some(0)), Some(0));
        assert_eq!(match_ordinal(&positions, Some(4)), Some(1));
        assert_eq!(match_ordinal(&positions, Some(10)), Some(2));
        assert_eq!(match_ordinal(&positions, Some(1)), None);
        assert_eq!(match_ordinal(&positions, None), None);
    }

    #[test]
    fn highlight_lookup_binary_search_requires_sorted_ranges() {
        // If match ranges are not sorted, the binary_search-based lookup in bytes_to_pretty_lines
        // will miss some highlights. This test documents the requirement.
        let bytes = b"abxxab";
        let ranges_unsorted = vec![(4usize, 6usize), (0usize, 2usize)];

        let any_style = style_any_match();

        // Unsorted: only one of the two occurrences is likely to be highlighted.
        let line_unsorted = bytes_to_pretty_lines(bytes, &ranges_unsorted, None);
        let a_hex_unsorted: Vec<_> = line_unsorted[0]
            .spans
            .iter()
            .filter(|s| s.content.as_ref() == "61")
            .collect();
        assert_eq!(a_hex_unsorted.len(), 2);
        let highlighted_unsorted = a_hex_unsorted
            .iter()
            .filter(|s| s.style == any_style)
            .count();
        assert_eq!(highlighted_unsorted, 1);

        // Sorted: both occurrences should be highlighted.
        let mut ranges_sorted = ranges_unsorted.clone();
        ranges_sorted.sort_unstable();
        let line_sorted = bytes_to_pretty_lines(bytes, &ranges_sorted, None);
        let a_hex_sorted: Vec<_> = line_sorted[0]
            .spans
            .iter()
            .filter(|s| s.content.as_ref() == "61")
            .collect();
        assert_eq!(a_hex_sorted.len(), 2);
        let highlighted_sorted = a_hex_sorted.iter().filter(|s| s.style == any_style).count();
        assert_eq!(highlighted_sorted, 2);
    }

    #[test]
    fn highlight_all_matches_cap_affects_collected_positions() {
        // With a small cap, we should collect fewer matches than exist.
        let bytes = b"ab".repeat(300);
        let needle = b"ab";

        let small_cap = (STREAM_MATCH_HIGHLIGHT_CAP / 10).max(1);
        let small = crate::search::find_all_subslice_positions(&bytes, needle, small_cap);
        let big =
            crate::search::find_all_subslice_positions(&bytes, needle, STREAM_MATCH_HIGHLIGHT_CAP);

        assert_eq!(small.len(), small_cap.min(300));
        assert_eq!(big.len(), 300);
    }

    #[test]
    fn manual_scroll_does_not_clear_current_match() {
        // This is a behavioral test of App's scroll methods.
        // Scrolling is purely a view offset and should not clear the active match selection.
        let mut app = App::new(
            "/tmp/nope.pcap",
            Vec::new(),
            FlowIndex { flows: Vec::new() },
        );
        app.view = View::Stream;
        app.stream_last_match = Some(123);
        app.stream_scroll = 10;

        app.scroll_down();
        assert_eq!(app.stream_last_match, Some(123));

        app.scroll_up();
        assert_eq!(app.stream_last_match, Some(123));
    }

    #[test]
    fn ascii_column_shows_tab_and_newline_glyphs() {
        let bytes = b"a\tb\n";
        let lines = bytes_to_pretty_lines(bytes, &[], None);
        assert_eq!(lines.len(), 1);

        let spans = &lines[0].spans;
        assert!(spans.iter().any(|s| s.content.as_ref() == "⇥"));
        assert!(spans.iter().any(|s| s.content.as_ref() == "⏎"));
    }

    #[test]
    fn hexdump_offset_is_right_aligned_no_leading_zeroes() {
        let bytes = b"a";
        let lines = bytes_to_pretty_lines(bytes, &[], None);
        let spans = &lines[0].spans;

        // First span is the offset column.
        let offset = &spans[0].content;
        assert!(offset.ends_with("  "));
        // Should contain spaces then a single '0' (not "00000000").
        assert!(offset.contains("0x     0"));
        assert!(!offset.contains("00000000"));
    }

    #[test]
    fn stream_title_uses_1_based_index_when_matches_exist() {
        // Construct a minimal scenario where there are matches but no current selection.
        let match_positions = vec![10usize, 20usize];
        let total = match_positions.len();
        let cur = match_ordinal(&match_positions, None)
            .map(|i| i + 1)
            .unwrap_or(0);
        let cur_disp = if total == 0 { 0 } else { cur.max(1) };
        assert_eq!(cur_disp, 1);
    }

    #[test]
    fn fmt_hexdump_offset_is_fixed_width_with_prefix() {
        let s = fmt_hexdump_offset(0);
        assert!(s.starts_with("0x"));
        assert!(s.ends_with("  "));
        // width: "0x" + 6 hex-padded-with-spaces + 2 spaces
        assert_eq!(s.len(), 10);
        assert!(s.contains("0"));
    }

    #[test]
    fn match_styles_distinguish_current_from_other_matches() {
        assert_ne!(style_current_match(), style_any_match());
        assert_ne!(style_any_match(), style_any_match_base());
    }

    #[test]
    fn scroll_for_match_pos_returns_containing_row() {
        // With 16-byte rows, we return the containing 16-byte row.
        assert_eq!(scroll_for_match_pos(0), 0);
        assert_eq!(scroll_for_match_pos(15), 0);
        assert_eq!(scroll_for_match_pos(16), 1);
        assert_eq!(scroll_for_match_pos(31), 1);
        assert_eq!(scroll_for_match_pos(32), 2);
    }

    #[test]
    fn count_stream_matches_is_zero_when_query_empty() {
        let mut app = App::new(
            "/tmp/nope.pcap",
            Vec::new(),
            FlowIndex { flows: Vec::new() },
        );
        app.stream_search.clear();
        assert_eq!(app.count_stream_matches(b"abc"), 0);

        app.stream_search = "a".to_string();
        assert_eq!(app.count_stream_matches(b"aba"), 2);
    }

    #[test]
    fn stream_title_shows_zero_matches_text_when_no_hits() {
        let app_stream_search = "xyz";
        let total = 0usize;
        let status = if total == 0 {
            format!("  search=\"{}\" (0 matches)", app_stream_search)
        } else {
            unreachable!()
        };
        assert!(status.contains("0 matches"));
    }

    #[test]
    fn count_stream_matches_respects_highlight_cap() {
        let mut app = App::new(
            "/tmp/nope.pcap",
            Vec::new(),
            FlowIndex { flows: Vec::new() },
        );
        app.stream_search = "ab".to_string();

        // 300 matches, but cap is 2000 so we should see all 300.
        let bytes = b"ab".repeat(300);
        assert_eq!(app.count_stream_matches(&bytes), 300);

        // If we exceed cap, we should stop at cap.
        let bytes = b"ab".repeat(STREAM_MATCH_HIGHLIGHT_CAP + 10);
        assert_eq!(app.count_stream_matches(&bytes), STREAM_MATCH_HIGHLIGHT_CAP);
    }

    #[test]
    fn search_modal_uses_plural_no_matches_wording() {
        assert_eq!(STREAM_SEARCH_STATUS_NO_MATCHES, "no matches");
    }

    #[test]
    fn search_modal_status_type_to_search_is_stable() {
        assert_eq!(STREAM_SEARCH_STATUS_TYPE_TO_SEARCH, "type to search");
    }

    #[test]
    fn stream_search_modal_help_mentions_navigation_keys() {
        assert!(STREAM_SEARCH_MODAL_HELP.contains("n/N"));
        assert!(STREAM_SEARCH_MODAL_HELP.contains("Tab"));
        assert!(STREAM_SEARCH_MODAL_HELP.contains("Shift-Tab"));
    }

    #[test]
    fn fmt_hexdump_offset_uses_placeholder_for_huge_offsets() {
        assert_eq!(fmt_hexdump_offset(0x1_0000), HEXDUMP_OFFSET_TOO_LARGE);
    }

    #[test]
    fn fmt_hexdump_offset_at_lut_max_is_not_placeholder() {
        let s = fmt_hexdump_offset(HEXDUMP_OFFSET_LUT_MAX);
        assert_ne!(s, HEXDUMP_OFFSET_TOO_LARGE);
        assert!(s.starts_with("0x"));
    }

    #[test]
    fn byte_in_any_range_works_for_simple_ranges() {
        let ranges = vec![(0usize, 2usize), (4usize, 6usize)];
        assert!(byte_in_any_range(0, &ranges));
        assert!(byte_in_any_range(1, &ranges));
        assert!(!byte_in_any_range(2, &ranges));
        assert!(!byte_in_any_range(3, &ranges));
        assert!(byte_in_any_range(4, &ranges));
        assert!(byte_in_any_range(5, &ranges));
        assert!(!byte_in_any_range(6, &ranges));
    }

    #[test]
    fn current_match_style_is_not_dimmed() {
        assert_ne!(
            style_current_match(),
            style_current_match().add_modifier(Modifier::DIM),
        );
    }

    #[test]
    fn stream_title_appends_plus_when_match_count_is_capped() {
        let total = STREAM_MATCH_HIGHLIGHT_CAP;
        assert_eq!(match_cap_suffix(total), "+");
    }

    #[test]
    fn stream_tab_prev_cycles_backward() {
        let mut app = App::new(
            "/tmp/nope.pcap",
            Vec::new(),
            FlowIndex { flows: Vec::new() },
        );
        app.stream_tab = StreamTab::Combined;
        app.tab_prev();
        assert!(matches!(app.stream_tab, StreamTab::BtoA));
        app.tab_prev();
        assert!(matches!(app.stream_tab, StreamTab::AtoB));
        app.tab_prev();
        assert!(matches!(app.stream_tab, StreamTab::Combined));
    }

    #[test]
    fn canceling_stream_search_resets_scroll() {
        let mut app = App::new(
            "/tmp/nope.pcap",
            Vec::new(),
            FlowIndex { flows: Vec::new() },
        );
        app.modal = Modal::StreamSearch;
        app.stream_scroll = 42;
        app.close_modal_cancel();
        assert_eq!(app.stream_scroll, 0);
    }

    #[test]
    fn applying_stream_search_without_flow_does_not_reset_scroll() {
        let mut app = App::new(
            "/tmp/nope.pcap",
            Vec::new(),
            FlowIndex { flows: Vec::new() },
        );
        app.modal = Modal::StreamSearch;
        app.view = View::Stream;
        app.stream_scroll = 7;
        app.stream_search = "zzz".to_string();

        app.close_modal_apply();

        // With no selected flow, applying the search should not disturb the current scroll.
        assert_eq!(app.stream_scroll, 7);
    }

    #[test]
    fn first_match_and_scroll_returns_scroll_row_for_match() {
        let bytes = vec![b'x'; 40];
        // Put "ab" at pos 32.
        let mut bytes = bytes;
        bytes[32] = b'a';
        bytes[33] = b'b';

        let (pos, scroll) = first_match_and_scroll(&bytes, b"ab").unwrap();
        assert_eq!(pos, 32);
        assert_eq!(scroll, 2);
    }

    #[test]
    fn next_prev_match_helpers_compute_scroll_for_later_rows() {
        let mut bytes = vec![b'x'; 40];
        bytes[32] = b'a';
        bytes[33] = b'b';

        let (pos, scroll) = next_match_and_scroll(&bytes, b"ab", None).unwrap();
        assert_eq!(pos, 32);
        assert_eq!(scroll, 2);

        let (pos, scroll) = prev_match_and_scroll(&bytes, b"ab", None).unwrap();
        assert_eq!(pos, 32);
        assert_eq!(scroll, 2);
    }

    #[test]
    fn opening_stream_search_resets_scroll() {
        let mut app = App::new(
            "/tmp/nope.pcap",
            Vec::new(),
            FlowIndex { flows: Vec::new() },
        );
        app.view = View::Stream;
        app.stream_scroll = 9;
        app.open_stream_search();
        assert_eq!(app.stream_scroll, 0);
    }
}

const STREAM_SEARCH_MODAL_TITLE: &str = "Stream search";
const STREAM_SEARCH_MODAL_HELP: &str =
    "Enter = apply   Esc = cancel   Ctrl+u = clear   (n/N next/prev, Tab/Shift-Tab switch stream)";
const STREAM_SEARCH_STATUS_TYPE_TO_SEARCH: &str = "type to search";
const STREAM_SEARCH_STATUS_MATCH_FOUND: &str = "match found (n/N to navigate)";
const STREAM_SEARCH_STATUS_NO_MATCHES: &str = "no matches";

fn render_search_modal(
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
                format!("{match_count}"),
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
