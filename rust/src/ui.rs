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

#[derive(Debug, Clone)]
enum OverviewAction {
    GoFlows,
    GoWeird,
    // Domains view will live here later.
    Port(u16),
    Host(std::net::IpAddr),
    FlowIndex(usize),
}

#[derive(Debug, Clone)]
struct OverviewRow {
    label: Line<'static>,
    action: Option<OverviewAction>,
}

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
    Overview,
    Flows,
    Weird,
    Domains,
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
    Explain,
    Glossary,
    Help,
}

pub struct App {
    pub pcap_path: PathBuf,
    pub live_iface: Option<String>,
    pub live_rx: Option<std::sync::mpsc::Receiver<crate::pcap::PacketRow>>,
    pub live_err_rx: Option<std::sync::mpsc::Receiver<String>>,
    pub live_last_stderr: Option<String>,
    pub live_total_packets: usize,
    pub live_pps: f64,
    pub live_capture_start: std::time::Instant,
    pub live_dropped_packets: usize,

    // onboarding
    pub show_onboarding: bool,

    // learning mode
    pub learning_mode: bool,
    pub live_pps_window_start: std::time::Instant,
    pub live_pps_window_count: usize,
    pub live_pending_rebuild: usize,
    pub casefile: CaseFile,

    pub rows: Vec<PacketRow>,
    pub flows: FlowIndex,

    pub view: View,

    // navigation
    pub flows_back_view: View,

    // overview dashboard selection
    pub overview_selected_row: usize,

    // flows selection is by index into `visible_flow_indices`
    pub selected_row: usize,
    pub visible_flow_indices: Vec<usize>,

    // packets view state
    pub packets_selected_row: usize,
    pub packets_scroll_row: usize,
    pub packets_viewport_rows: usize,

    // weird-mode (detector) state
    pub weird_selected_row: usize,

    // domains-mode state
    pub domains_selected_row: usize,
    pub domains_sort: crate::domains::DomainsSort,

    // active flow subset (used by Weird + Domains drilldown)
    pub flow_subset: Option<Vec<usize>>, // flow indices (into flows.flows)
    pub subset_label: Option<String>,

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
            live_iface: None,
            live_rx: None,
            live_err_rx: None,
            live_last_stderr: None,
            live_total_packets: 0,
            live_pps: 0.0,
            live_capture_start: std::time::Instant::now(),
            live_dropped_packets: 0,
            show_onboarding: true,
            learning_mode: false,
            live_pps_window_start: std::time::Instant::now(),
            live_pps_window_count: 0,
            live_pending_rebuild: 0,
            casefile,
            rows,
            flows,
            view: View::Overview,
            flows_back_view: View::Overview,
            overview_selected_row: 0,
            selected_row: 0,
            visible_flow_indices: Vec::new(),
            packets_selected_row: 0,
            packets_scroll_row: 0,
            packets_viewport_rows: 0,
            weird_selected_row: 0,
            domains_selected_row: 0,
            domains_sort: crate::domains::DomainsSort::Connections,
            flow_subset: None,
            subset_label: None,
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
        // Base set: filter text + TCP/UDP toggles.
        let mut indices: Vec<usize> = self
            .flows
            .flows
            .iter()
            .enumerate()
            .filter(|(_i, f)| self.filter.matches(f))
            .map(|(i, _)| i)
            .collect();

        // Optional additional subset restriction (used by Weird-mode detectors).
        if let Some(subset) = &self.flow_subset {
            // `subset` is stored sorted; use binary_search for cheap intersection.
            indices.retain(|i| subset.binary_search(i).is_ok());
        }

        self.visible_flow_indices = indices;

        if self.selected_row >= self.visible_flow_indices.len() {
            self.selected_row = self.visible_flow_indices.len().saturating_sub(1);
        }
    }

    fn apply_filter(&mut self) {
        self.recompute_visible();
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
        self.packets_selected_row = 0;
        self.packets_scroll_row = 0;
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
            View::Weird => View::Flows,
            View::Domains => View::Flows,
            View::Packets => View::Flows,
            View::Stream => View::Packets,
            View::Overview => View::Overview,
        };
        self.stream_scroll = 0;
    }

    /// Recompute `stream_match_count` for the current stream view/tab
    /// (based on the current `stream_search` query), if a flow is selected.
    fn refresh_stream_match_count(&mut self) {
        if self.view == View::Stream {
            if let Some(fl) = self.selected_flow() {
                let bytes = build_stream_bytes(&self.rows, fl, self.stream_tab);
                self.stream_match_count = self.count_stream_matches(&bytes);
            }
        }
    }

    fn compute_live_drop(current_len: usize, cap: usize) -> usize {
        current_len.saturating_sub(cap)
    }

    fn poll_live(&mut self) {
        const LIVE_CAP: usize = 20_000;
        const REBUILD_EVERY: usize = 200;

        // Drain stderr (even if idle) so we can surface useful live errors.
        if let Some(err_rx) = self.live_err_rx.as_ref() {
            // Keep only the most recent line.
            while let Ok(line) = err_rx.try_recv() {
                let line = line.trim().to_string();
                if !line.is_empty() {
                    self.live_last_stderr = Some(line);
                }
            }
        }

        let Some(rx) = self.live_rx.as_ref() else {
            return;
        };

        let mut added: usize = 0;
        while let Ok(mut row) = rx.try_recv() {
            row.index = self.rows.len();
            self.rows.push(row);
            self.live_total_packets += 1;
            self.live_pps_window_count += 1;
            self.live_pending_rebuild += 1;
            added += 1;
        }

        if added == 0 {
            // update pps window even if idle
            if self.live_pps_window_start.elapsed().as_secs_f64() >= 1.0 {
                let dt = self.live_pps_window_start.elapsed().as_secs_f64();
                if dt > 0.0 {
                    self.live_pps = (self.live_pps_window_count as f64) / dt;
                }
                self.live_pps_window_start = std::time::Instant::now();
                self.live_pps_window_count = 0;
            }
            return;
        }

        // cap buffer (drop oldest) and renumber indices so FlowIndex packet_indices remain valid.
        if self.rows.len() > LIVE_CAP {
            let drop = Self::compute_live_drop(self.rows.len(), LIVE_CAP);
            self.live_dropped_packets += drop;
            self.rows.drain(0..drop);
            for (i, r) in self.rows.iter_mut().enumerate() {
                r.index = i;
            }
        }

        // periodically rebuild flows + visible indices.
        if self.live_pending_rebuild >= REBUILD_EVERY {
            self.flows = FlowIndex::build(&self.rows);
            self.apply_filter();
            self.live_pending_rebuild = 0;
        }

        if self.live_pps_window_start.elapsed().as_secs_f64() >= 1.0 {
            let dt = self.live_pps_window_start.elapsed().as_secs_f64();
            if dt > 0.0 {
                self.live_pps = (self.live_pps_window_count as f64) / dt;
            }
            self.live_pps_window_start = std::time::Instant::now();
            self.live_pps_window_count = 0;
        }
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
        if self.view != View::Stream {
            // Only meaningful in Stream view; keep other views from mutating stream-tab state.
            self.stream_last_match = None;
            self.stream_match_count = 0;
            return;
        }

        self.stream_tab = match self.stream_tab {
            StreamTab::Combined => StreamTab::AtoB,
            StreamTab::AtoB => StreamTab::BtoA,
            StreamTab::BtoA => StreamTab::Combined,
        };
        self.stream_scroll = 0;

        // Preserve search context when switching tabs: if we have a query,
        // jump to the first match in the new stream view.
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

    fn tab_prev(&mut self) {
        if self.view != View::Stream {
            self.stream_last_match = None;
            self.stream_match_count = 0;
            return;
        }

        self.stream_tab = match self.stream_tab {
            StreamTab::Combined => StreamTab::BtoA,
            StreamTab::AtoB => StreamTab::Combined,
            StreamTab::BtoA => StreamTab::AtoB,
        };
        self.stream_scroll = 0;

        // Preserve search context when switching tabs.
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

        self.refresh_stream_match_count();

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
            Modal::Explain => {
                // no-op; explain modal has nothing to apply
            }
            Modal::Glossary => {
                // read-only modal
            }
            Modal::Help => {
                // read-only modal
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

                self.refresh_stream_match_count();
            }
            Modal::Explain => {
                // read-only modal
            }
            Modal::Glossary => {
                // read-only modal
            }
            Modal::Help => {
                // read-only modal
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

                self.refresh_stream_match_count();
            }
            Modal::Explain => {
                // read-only modal
            }
            Modal::Glossary => {
                // read-only modal
            }
            Modal::Help => {
                // read-only modal
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
            Modal::Explain => {
                // read-only modal
            }
            Modal::Glossary => {
                // read-only modal
            }
            Modal::Help => {
                // read-only modal
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

fn match_cap_suffix(count: usize) -> &'static str {
    if count >= STREAM_MATCH_HIGHLIGHT_CAP {
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

fn build_overview_rows(app: &App) -> Vec<OverviewRow> {
    use crate::summary::build_overview;

    let ov = build_overview(&app.rows, &app.flows, 10);
    let weird = crate::weird::build_weird_summary(&app.rows, &app.flows);

    let mut rows: Vec<OverviewRow> = Vec::new();

    if app.show_onboarding {
        rows.push(OverviewRow {
            label: Line::from(vec![Span::styled(
                "New here?",
                Style::default().fg(Color::Rgb(255, 215, 0)).add_modifier(Modifier::BOLD),
            )]),
            action: None,
        });
        rows.push(OverviewRow {
            label: Line::from(vec![
                Span::styled("• ", Style::default().fg(c_muted())),
                Span::styled("Press D", Style::default().fg(c_accent()).add_modifier(Modifier::BOLD)),
                Span::styled(" for Domains (human view)", Style::default().fg(c_text())),
            ]),
            action: None,
        });
        rows.push(OverviewRow {
            label: Line::from(vec![
                Span::styled("• ", Style::default().fg(c_muted())),
                Span::styled("Press W", Style::default().fg(c_accent()).add_modifier(Modifier::BOLD)),
                Span::styled(" for Weird stuff (troubleshoot)", Style::default().fg(c_text())),
            ]),
            action: None,
        });
        rows.push(OverviewRow {
            label: Line::from(vec![
                Span::styled("• ", Style::default().fg(c_muted())),
                Span::styled("Press F", Style::default().fg(c_accent()).add_modifier(Modifier::BOLD)),
                Span::styled(" for Flows (raw)", Style::default().fg(c_text())),
            ]),
            action: None,
        });
        rows.push(OverviewRow {
            label: Line::from(vec![
                Span::styled("• ", Style::default().fg(c_muted())),
                Span::styled("Press h", Style::default().fg(c_accent()).add_modifier(Modifier::BOLD)),
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
            Span::styled("Domains (human view)", Style::default().fg(Color::Rgb(255, 215, 0)).add_modifier(Modifier::BOLD)),
            Span::styled("  (press D)", Style::default().fg(c_muted())),
        ]),
        // Domains row uses a dedicated keybind; make it obvious even if Enter does nothing.
        action: None,
    });

    rows.push(OverviewRow {
        label: Line::from(vec![
            Span::styled("• ", Style::default().fg(c_muted())),
            Span::styled("Weird stuff (troubleshoot)", Style::default().fg(Color::Rgb(255, 215, 0)).add_modifier(Modifier::BOLD)),
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
            format!("TCP: {}  UDP: {}  Other: {}", ov.protos.tcp, ov.protos.udp, ov.protos.other),
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
                Span::styled(format!("{}B", fl.total_bytes), Style::default().fg(c_muted())),
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

fn run_loop(terminal: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App) -> Result<()> {
    let mut flow_state = ListState::default();
    if !app.visible_flow_indices.is_empty() {
        flow_state.select(Some(app.selected_row));
    }

    loop {
        app.poll_live();

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
                View::Overview => "Overview",
                View::Flows => "Flows",
                View::Weird => "Weird stuff",
                View::Domains => "Domains",
                View::Packets => "Packets",
                View::Stream => "Follow Stream",
            };

            let mut filter_badge = format!(
                "tcp:{} udp:{} q={}",
                if app.filter.show_tcp { "on" } else { "off" },
                if app.filter.show_udp { "on" } else { "off" },
                if app.filter.query.trim().is_empty() {
                    "—"
                } else {
                    app.filter.query.trim()
                }
            );
            if let Some(lbl) = &app.subset_label {
                filter_badge.push_str(&format!("  subset={lbl}"));
            }

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
                View::Overview => {
                    let rows = build_overview_rows(app);

                    // Build list items + state
                    let items: Vec<ListItem> = rows
                        .iter()
                        .map(|r| {
                            let st = if r.action.is_some() {
                                Style::default().fg(c_text())
                            } else {
                                Style::default().fg(c_muted())
                            };
                            ListItem::new(r.label.clone()).style(st)
                        })
                        .collect();

                    let mut overview_state = ListState::default();
                    if !items.is_empty() {
                        // Clamp selection.
                        app.overview_selected_row = app.overview_selected_row.min(items.len() - 1);
                        overview_state.select(Some(app.overview_selected_row));
                    }

                    let list = List::new(items)
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title("Overview  (D domains, W weird, F flows)")
                                .style(Style::default().bg(c_panel())),
                        )
                        .highlight_style(
                            Style::default()
                                .bg(c_highlight_bg())
                                .fg(c_text())
                                .add_modifier(Modifier::BOLD),
                        )
                        .highlight_symbol("❯ ");

                    f.render_stateful_widget(list, body_chunks[0], &mut overview_state);

                    // Store rows in a local closure via a tiny hack: we re-build on Enter.
                }

                View::Weird => {
                    use crate::weird::build_weird_summary;

                    let weird = build_weird_summary(&app.rows, &app.flows);

                    let items: Vec<ListItem> = weird
                        .items
                        .iter()
                        .enumerate()
                        .map(|(i, it)| {
                            let line = Line::from(vec![
                                Span::styled(
                                    format!("{:>2} ", i + 1),
                                    Style::default().fg(c_muted()),
                                ),
                                Span::styled(
                                    format!("{:<22}", it.title),
                                    Style::default().fg(c_text()).add_modifier(Modifier::BOLD),
                                ),
                                Span::raw(UI_SPACER),
                                Span::styled(
                                    format!("flows={}", it.flow_indices.len()),
                                    Style::default().fg(if it.flow_indices.is_empty() {
                                        Color::Rgb(160, 170, 190)
                                    } else {
                                        Color::Rgb(255, 215, 0)
                                    }),
                                ),
                            ]);
                            ListItem::new(line)
                        })
                        .collect();

                    let mut weird_state = ListState::default();
                    if !weird.items.is_empty() {
                        weird_state.select(Some(app.weird_selected_row.min(weird.items.len() - 1)));
                    }

                    let list = List::new(items)
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title("Weird stuff  (Enter show flows, c clear, Esc back)")
                                .style(Style::default().bg(c_panel())),
                        )
                        .highlight_style(
                            Style::default()
                                .bg(c_highlight_bg())
                                .fg(c_text())
                                .add_modifier(Modifier::BOLD),
                        )
                        .highlight_symbol("❯ ");

                    f.render_stateful_widget(list, body_chunks[0], &mut weird_state);

                    // Right panel: explanation
                    let selected = weird.items.get(app.weird_selected_row);
                    let (title, why, next) = if let Some(it) = selected {
                        (it.title.as_str(), it.why.as_str(), it.next.as_str())
                    } else {
                        ("Weird stuff", "Pick a detector on the left.", "")
                    };

                    let mut expl_lines: Vec<Line> = vec![
                        Line::from(Span::styled(
                            title,
                            Style::default().fg(c_accent()).add_modifier(Modifier::BOLD),
                        )),
                        Line::from(Span::raw("")),
                        Line::from(Span::styled(why, Style::default().fg(c_text()))),
                    ];

                    if !next.trim().is_empty() {
                        expl_lines.push(Line::from(Span::raw("")));
                        expl_lines.push(Line::from(Span::styled(
                            format!("Next: {next}"),
                            Style::default().fg(c_muted()),
                        )));
                    }

                    expl_lines.push(Line::from(Span::raw("")));
                    expl_lines.push(Line::from(Span::styled(
                        "Tip: Enter applies a flow filter so you can drill into packets/stream.",
                        Style::default().fg(c_muted()),
                    )));

                    let expl = Paragraph::new(expl_lines)

                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title("Why it matters")
                            .style(Style::default().bg(c_panel())),
                    )
                    .wrap(Wrap { trim: true });

                    f.render_widget(expl, body_chunks[1]);
                }

                View::Domains => {
                    use crate::domains::build_domains_summary;

                    let dom = build_domains_summary(&app.rows, &app.flows, app.domains_sort);

                    let items: Vec<ListItem> = dom
                        .items
                        .iter()
                        .enumerate()
                        .map(|(i, it)| {
                            let line = Line::from(vec![
                                Span::styled(format!("{:>2} ", i + 1), Style::default().fg(c_muted())),
                                Span::styled(
                                    format!("{:<28}", it.domain),
                                    Style::default().fg(c_text()).add_modifier(Modifier::BOLD),
                                ),
                                Span::raw(UI_SPACER),
                                Span::styled(
                                    format!(
                                        "conn={} bytes={:.1}KB q={} r={} fail={} ips={}{}",
                                        it.stats.connections,
                                        (it.stats.bytes as f64) / 1024.0,
                                        it.stats.queries,
                                        it.stats.responses,
                                        it.stats.failures,
                                        it.stats.observed_ips.len().max(it.stats.dns_ips.len()),
                                        if !it.stats.observed_ips.is_empty() && it.stats.dns_ips.is_empty() {
                                            "*"
                                        } else {
                                            ""
                                        }
                                    ),
                                    Style::default().fg(if it.stats.failures > 0 {
                                        Color::Rgb(255, 215, 0)
                                    } else {
                                        c_muted()
                                    }),
                                ),
                            ]);
                            ListItem::new(line)
                        })
                        .collect();

                    let mut dom_state = ListState::default();
                    if !dom.items.is_empty() {
                        app.domains_selected_row = app.domains_selected_row.min(dom.items.len() - 1);
                        dom_state.select(Some(app.domains_selected_row));
                    }

                    let list = List::new(items)
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title("Domains  (Enter show flows, s sort (conn/bytes/fail), c clear, Esc back)")
                                .style(Style::default().bg(c_panel())),
                        )
                        .highlight_style(
                            Style::default()
                                .bg(c_highlight_bg())
                                .fg(c_text())
                                .add_modifier(Modifier::BOLD),
                        )
                        .highlight_symbol("❯ ");

                    f.render_stateful_widget(list, body_chunks[0], &mut dom_state);

                    let selected = dom.items.get(app.domains_selected_row);
                    let right = if let Some(it) = selected {
                        let observed: Vec<String> = it
                            .stats
                            .observed_ips
                            .iter()
                            .take(12)
                            .map(|ip| ip.to_string())
                            .collect();
                        let dns: Vec<String> = it
                            .stats
                            .dns_ips
                            .iter()
                            .take(12)
                            .map(|ip| ip.to_string())
                            .collect();

                        let mut out: Vec<Line> = vec![
                            Line::from(Span::styled(
                                it.domain.clone(),
                                Style::default().fg(c_accent()).add_modifier(Modifier::BOLD),
                            )),
                            Line::from(Span::raw("")),
                            Line::from(Span::styled(
                                format!(
                                    "queries={} responses={} failures={}",
                                    it.stats.queries, it.stats.responses, it.stats.failures
                                ),
                                Style::default().fg(c_text()),
                            )),
                            Line::from(Span::raw("")),
                        ];

                        if !observed.is_empty() {
                            out.push(Line::from(Span::styled(
                                "Observed IPs (from flows):",
                                Style::default().fg(c_muted()).add_modifier(Modifier::BOLD),
                            )));
                            for l in observed {
                                out.push(Line::from(Span::styled(l, Style::default().fg(c_text()))));
                            }
                            out.push(Line::from(Span::raw("")));
                        }

                        if !dns.is_empty() {
                            out.push(Line::from(Span::styled(
                                "DNS A/AAAA IPs (when visible):",
                                Style::default().fg(c_muted()).add_modifier(Modifier::BOLD),
                            )));
                            for l in dns {
                                out.push(Line::from(Span::styled(l, Style::default().fg(c_text()))));
                            }
                            out.push(Line::from(Span::raw("")));
                        }

                        if out.len() <= 4 {
                            // No IP hints were added.
                            out.push(Line::from(Span::styled(
                                "IP hints:",
                                Style::default().fg(c_muted()).add_modifier(Modifier::BOLD),
                            )));
                            out.push(Line::from(Span::styled(
                                "(no IPs observed yet — likely DoH/DoT or cached DNS)",
                                Style::default().fg(c_text()),
                            )));
                            out.push(Line::from(Span::raw("")));
                        }

                        out.push(Line::from(Span::styled(
                            "Tip: Enter applies a subset filter (prefers observed IPs; DNS IPs if available).",
                            Style::default().fg(c_muted()),
                        )));
                        out.push(Line::from(Span::styled(
                            "Note: ips=* means observed-only (no DNS answers seen in capture).",
                            Style::default().fg(c_muted()),
                        )));

                        out
                    } else {
                        vec![Line::from(Span::styled(
                            "No domains found.",
                            Style::default().fg(c_muted()),
                        ))]
                    };

                    let p = Paragraph::new(right)
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title("Domain details")
                                .style(Style::default().bg(c_panel())),
                        )
                        .wrap(Wrap { trim: true });
                    f.render_widget(p, body_chunks[1]);
                }

                View::Flows => {
                    let ip_host = crate::domains::build_ip_hostname_index(&app.rows);

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

                            // Best-effort: label the dst IP (server-ish) with a hostname when known.
                            let host = ip_host
                                .get(&fl.key.dst)
                                .or_else(|| ip_host.get(&fl.key.src))
                                .cloned();

                            let mut spans = vec![
                                Span::styled(
                                    format!("{:>3} ", row_i + 1),
                                    Style::default().fg(c_muted()),
                                ),
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
                            ];

                            if let Some(h) = host {
                                spans.push(Span::raw(UI_SPACER));
                                spans.push(Span::styled(
                                    format!("[{h}]"),
                                    Style::default().fg(Color::Rgb(160, 170, 190)),
                                ));
                            }

                            Some(ListItem::new(Line::from(spans)))
                        })
                        .collect();

                    let list = List::new(items)
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title(if let Some(iface) = &app.live_iface {
                                    format!(
                                        "Flows [LIVE {iface}] ({:.1} pps)  (Enter packets, / filter, t/u toggles, b bookmark, E export, o overview)",
                                        app.live_pps
                                    )
                                } else {
                                    "Flows  (Enter packets, / filter, t/u toggles, b bookmark, E export, o overview)".to_string()
                                })
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

                    let ip_host = crate::domains::build_ip_hostname_index(&app.rows);

                    let mut items: Vec<ListItem> = Vec::with_capacity(fl.packet_indices.len());

                    let mut prev_ts: Option<chrono::DateTime<chrono::Utc>> = None;

                    for idx in fl.packet_indices.iter() {
                        let Some(r) = app.rows.get(*idx) else {
                            continue;
                        };

                        let dir = match r.flow_dir {
                            Some(FlowDir::AtoB) => "→",
                            Some(FlowDir::BtoA) => "←",
                            None => "·",
                        };

                        let ts_str = r.ts.format("%H:%M:%S%.3f").to_string();
                        let delta_str = if let Some(prev) = prev_ts {
                            let d = r.ts.signed_duration_since(prev);
                            let ms = d.num_microseconds().unwrap_or(0) as f64 / 1000.0;
                            format!("{ms:+8.3}ms")
                        } else {
                            format!("{ms:+8.3}ms", ms = 0.0)
                        };
                        prev_ts = Some(r.ts);

                        let mut spans = vec![
                            Span::styled(dir, Style::default().fg(c_accent())),
                            Span::raw(UI_ONE_SPACE),
                            Span::styled(format!("#{:<4} ", r.index), Style::default().fg(c_muted())),
                            Span::styled(ts_str, Style::default().fg(Color::Rgb(200, 200, 210))),
                            Span::raw(UI_SPACER),
                            Span::styled(delta_str, Style::default().fg(Color::Rgb(160, 170, 190))),
                            Span::raw(UI_SPACER),
                            Span::styled(
                                format!("{:>4}B ", r.len),
                                Style::default().fg(Color::Rgb(190, 200, 220)),
                            ),
                            Span::styled(
                                r.tcp_flags
                                    .map(crate::pcap::tcp_flags_to_string)
                                    .filter(|s| !s.is_empty())
                                    .map(|s| format!("[{s}] "))
                                    .unwrap_or_default(),
                                Style::default().fg(Color::Rgb(180, 190, 210)),
                            ),
                        ];

                        if let Some(dst) = r.dst {
                            if let Some(h) = ip_host.get(&dst) {
                                spans.push(Span::styled(
                                    format!("{h} "),
                                    Style::default().fg(Color::Rgb(160, 170, 190)),
                                ));
                            }
                        }

                        spans.push(Span::styled(r.summary.clone(), Style::default().fg(c_text())));

                        let line = Line::from(spans);

                        items.push(ListItem::new(line));
                    }

                    // Update viewport for paging.
                    app.packets_viewport_rows = body_chunks[0].height.saturating_sub(2) as usize;

                    if !items.is_empty() {
                        app.packets_selected_row = app.packets_selected_row.min(items.len() - 1);
                    }

                    // Render a window for scrolling/paging.
                    let vp = app.packets_viewport_rows.max(1);
                    if app.packets_scroll_row > app.packets_selected_row {
                        app.packets_scroll_row = app.packets_selected_row;
                    }
                    if app.packets_selected_row >= app.packets_scroll_row + vp {
                        app.packets_scroll_row = app.packets_selected_row.saturating_sub(vp - 1);
                    }
                    if !items.is_empty() {
                        app.packets_scroll_row = app.packets_scroll_row.min(items.len().saturating_sub(1));
                    } else {
                        app.packets_scroll_row = 0;
                    }

                    let visible_items: Vec<ListItem> = items
                        .into_iter()
                        .skip(app.packets_scroll_row)
                        .take(vp)
                        .collect();

                    let mut pkt_state = ListState::default();
                    if !visible_items.is_empty() {
                        let rel = app.packets_selected_row.saturating_sub(app.packets_scroll_row);
                        pkt_state.select(Some(rel.min(visible_items.len() - 1)));
                    }

                    let list = List::new(visible_items)
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title("Packets  (↑/↓ move, PgUp/PgDn page, f follow stream, ? explain, Esc back)")
                                .style(Style::default().bg(c_panel())),
                        )
                        .highlight_style(
                            Style::default()
                                .bg(c_highlight_bg())
                                .fg(c_text())
                                .add_modifier(Modifier::BOLD),
                        )
                        .highlight_symbol("❯ ");

                    f.render_stateful_widget(list, body_chunks[0], &mut pkt_state);
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

            // Details panel (skip for views that own the right pane)
            if !matches!(app.view, View::Weird | View::Domains | View::Overview) {
                let detail = if let Some(fl) = app.selected_flow() {
                    let a =
                        format!("A→B: {} pkts / {} bytes", fl.a_to_b.packets, fl.a_to_b.bytes);
                    let b =
                        format!("B→A: {} pkts / {} bytes", fl.b_to_a.packets, fl.b_to_a.bytes);
                    let bookmarks = app.casefile.bookmarks.len();

                    let mut out = vec![
                        Line::from(vec![Span::styled(
                            fl.label(),
                            Style::default()
                                .fg(Color::Rgb(255, 215, 0))
                                .add_modifier(Modifier::BOLD),
                        )]),
                        Line::from(Span::raw("")),
                        Line::from(Span::styled(a, Style::default().fg(c_muted()))),
                        Line::from(Span::styled(b, Style::default().fg(c_muted()))),
                        Line::from(Span::raw("")),
                        Line::from(vec![
                            Span::styled("bookmarks: ", Style::default().fg(c_muted())),
                            Span::raw(format!("{bookmarks}")),
                        ]),
                    ];

                    if app.learning_mode {
                        out.push(Line::from(Span::raw("")));
                        out.push(Line::from(Span::styled(
                            "Learning mode",
                            Style::default().fg(c_muted()).add_modifier(Modifier::BOLD),
                        )));
                        out.push(Line::from(Span::styled(
                            "A flow groups packets between two endpoints (IP:port ↔ IP:port).",
                            Style::default().fg(c_muted()),
                        )));
                        out.push(Line::from(Span::styled(
                            "Tip: Enter opens Packets; ? explains; / filters flows.",
                            Style::default().fg(c_muted()),
                        )));
                    }

                    out
                } else {
                    vec![Line::from(Span::styled(
                        "No flows decoded.",
                        Style::default().fg(c_muted()),
                    ))]
                };

                let detail = Paragraph::new(detail).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Details")
                        .style(Style::default().bg(c_panel())),
                );
                f.render_widget(detail, body_chunks[1]);
            }

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
                    Span::styled("type query, Enter apply, Esc/Backspace cancel, Ctrl+u clear", Style::default().fg(c_muted())),
                ]),
                Modal::Explain => Line::from(vec![
                    Span::styled("EXPLAIN", Style::default().fg(c_accent()).add_modifier(Modifier::BOLD)),
                    Span::raw(UI_SPACER),
                    Span::styled("Esc/Backspace close", Style::default().fg(c_muted())),
                ]),
                Modal::Glossary => Line::from(vec![
                    Span::styled("GLOSSARY", Style::default().fg(c_accent()).add_modifier(Modifier::BOLD)),
                    Span::raw(UI_SPACER),
                    Span::styled("Esc/Backspace close", Style::default().fg(c_muted())),
                ]),
                Modal::Help => Line::from(vec![
                    Span::styled("HELP", Style::default().fg(c_accent()).add_modifier(Modifier::BOLD)),
                    Span::raw(UI_SPACER),
                    Span::styled("Esc/Backspace close", Style::default().fg(c_muted())),
                ]),
                Modal::None => match app.view {
                    View::Overview => Line::from(vec![
                        Span::styled("F", Style::default().fg(Color::Green)),
                        Span::raw(" flows  "),
                        Span::styled("W", Style::default().fg(Color::Green)),
                        Span::raw(" weird  "),
                        Span::styled("D", Style::default().fg(Color::Green)),
                        Span::raw(" domains  "),
                        Span::styled("q", Style::default().fg(Color::Green)),
                        Span::raw(" quit"),
                    ]),
                    View::Weird => Line::from(vec![
                        Span::styled("↑/↓", Style::default().fg(Color::Green)),
                        Span::raw(" move  "),
                        Span::styled("Enter", Style::default().fg(Color::Green)),
                        Span::raw(" show flows  "),
                        Span::styled("c", Style::default().fg(Color::Green)),
                        Span::raw(" clear  "),
                        Span::styled("Esc", Style::default().fg(Color::Green)),
                        Span::raw(" back  "),
                        Span::styled("q", Style::default().fg(Color::Green)),
                        Span::raw(" quit"),
                    ]),
                    View::Domains => Line::from(vec![
                        Span::styled("↑/↓", Style::default().fg(Color::Green)),
                        Span::raw(" move  "),
                        Span::styled("Enter", Style::default().fg(Color::Green)),
                        Span::raw(" show flows  "),
                        Span::styled("c", Style::default().fg(Color::Green)),
                        Span::raw(" clear  "),
                        Span::styled("Esc", Style::default().fg(Color::Green)),
                        Span::raw(" back  "),
                        Span::styled("q", Style::default().fg(Color::Green)),
                        Span::raw(" quit"),
                    ]),
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
                        Span::styled("c", Style::default().fg(Color::Green)),
                        Span::raw(" clear weird  "),
                        Span::styled("q", Style::default().fg(Color::Green)),
                        Span::raw(" quit"),
                    ]),
                    View::Packets => Line::from(vec![
                        Span::styled("↑/↓", Style::default().fg(Color::Green)),
                        Span::raw(" move  "),
                        Span::styled("PgUp/PgDn", Style::default().fg(Color::Green)),
                        Span::raw(" page  "),
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
                        Span::styled("g", Style::default().fg(Color::Green)),
                        Span::raw(" glossary  "),
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
                Modal::Explain => {
                    let lines = build_explain_lines(app);
                    render_explain_modal(f, size, &lines);
                }
                Modal::Glossary => {
                    let lines = build_glossary_lines();
                    render_glossary_modal(f, size, &lines);
                }
                Modal::Help => {
                    let lines = build_help_lines();
                    render_help_modal(f, size, &lines);
                }
                Modal::None => {}
            }
        })?;

        // Input
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                // On some terminals/platforms (notably macOS), certain keys may show up as Repeat.
                // Treat Press+Repeat as input; ignore Release.
                if key.kind == KeyEventKind::Release {
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
                    KeyCode::Char('o') | KeyCode::Char('O') => { app.view = View::Overview; app.show_onboarding = false; },
                    KeyCode::Char('F') => { app.flows_back_view = app.view; app.view = View::Flows; app.show_onboarding = false; },
                    KeyCode::Char('W') | KeyCode::Char('w') => { app.view = View::Weird; app.show_onboarding = false; },
                    KeyCode::Char('D') | KeyCode::Char('d') => { app.view = View::Domains; app.show_onboarding = false; },
                    KeyCode::Char('f') => {
                        // lower-case f is "follow stream" in Packets; elsewhere treat as Flows shortcut.
                        if app.view == View::Packets {
                            app.open_stream();
                        } else {
                            app.flows_back_view = app.view;
                            app.view = View::Flows;
                        }
                        app.show_onboarding = false;
                    }
                    KeyCode::Char('?') => {
                        if matches!(app.view, View::Flows | View::Packets | View::Stream) {
                            app.modal = Modal::Explain;
                        }
                    }
                    KeyCode::Char('g') => {
                        app.modal = Modal::Glossary;
                        app.show_onboarding = false;
                    }
                    KeyCode::Char('h') => {
                        app.modal = Modal::Help;
                        app.show_onboarding = false;
                    }
                    KeyCode::Char('L') | KeyCode::Char('l') => {
                        app.learning_mode = !app.learning_mode;
                        app.show_onboarding = false;
                    }
                    KeyCode::Char('x') => {
                        if app.view == View::Overview {
                            app.show_onboarding = false;
                        }
                    }
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
                    KeyCode::Char('c') => {
                        if matches!(app.view, View::Flows | View::Weird | View::Domains) {
                            app.flow_subset = None;
                            app.subset_label = None;
                            app.apply_filter();
                        }
                    }
                    KeyCode::Char('s') => {
                        if app.view == View::Domains {
                            use crate::domains::DomainsSort;
                            app.domains_sort = match app.domains_sort {
                                DomainsSort::Connections => DomainsSort::Bytes,
                                DomainsSort::Bytes => DomainsSort::Failures,
                                DomainsSort::Failures => DomainsSort::Connections,
                            };
                        }
                    }
                    KeyCode::Esc | KeyCode::Backspace => {
                        // Esc/Backspace are the "go back" keys.
                        if app.view == View::Flows {
                            app.view = app.flows_back_view;
                        } else if app.view == View::Weird {
                            app.view = View::Overview;
                        } else if app.view == View::Domains {
                            app.view = View::Overview;
                        } else {
                            app.back();
                        }
                    }
                    KeyCode::Enter => {
                        if app.view == View::Flows {
                            app.open_packets();
                        } else if app.view == View::Weird {
                            let weird = crate::weird::build_weird_summary(&app.rows, &app.flows);
                            if weird.items.is_empty() {
                                // nothing
                            } else {
                                let sel = app.weird_selected_row.min(weird.items.len() - 1);
                                app.weird_selected_row = sel;
                                if let Some(it) = weird.items.get(sel) {
                                let mut subset = it.flow_indices.clone();
                                subset.sort_unstable();
                                subset.dedup();
                                app.flow_subset = Some(subset);
                                app.subset_label = Some(format!("weird:{}", it.title));
                                app.flows_back_view = View::Weird;
                                app.view = View::Flows;
                                app.selected_row = 0;
                                app.apply_filter();
                                flow_state.select(Some(app.selected_row));
                                }
                            }
                        } else if app.view == View::Domains {
                            let dom = crate::domains::build_domains_summary(
                                &app.rows,
                                &app.flows,
                                app.domains_sort,
                            );
                            if dom.items.is_empty() {
                                // nothing
                            } else {
                                let sel = app.domains_selected_row.min(dom.items.len() - 1);
                                app.domains_selected_row = sel;
                                if let Some(it) = dom.items.get(sel) {
                                let mut subset = it.flow_indices.clone();
                                subset.sort_unstable();
                                subset.dedup();
                                app.flow_subset = Some(subset);
                                app.subset_label = Some(format!("domain:{}", it.domain));
                                app.flows_back_view = View::Domains;
                                app.view = View::Flows;
                                app.selected_row = 0;
                                app.apply_filter();
                                flow_state.select(Some(app.selected_row));
                                }
                            }
                        } else if app.view == View::Overview {
                            // Rebuild the overview rows in the same order as the UI and execute the selected action.
                            let rows = build_overview_rows(app);
                            if rows.is_empty() {
                                // nothing
                            } else {
                                let sel = app.overview_selected_row.min(rows.len() - 1);
                                if let Some(action) = rows.get(sel).and_then(|r| r.action.clone()) {
                                    match action {
                                        OverviewAction::GoFlows => {
                                            app.flows_back_view = View::Overview;
                                            app.view = View::Flows;
                                        }
                                        OverviewAction::GoWeird => {
                                            app.view = View::Weird;
                                        }
                                        OverviewAction::Port(p) => {
                                            app.flow_subset = None;
                                            app.subset_label = None;
                                            app.filter.query = format!(":{p}");
                                            app.flows_back_view = View::Overview;
                                            app.view = View::Flows;
                                            app.selected_row = 0;
                                            app.apply_filter();
                                            flow_state.select(Some(app.selected_row));
                                        }
                                        OverviewAction::Host(ip) => {
                                            app.flow_subset = None;
                                            app.subset_label = None;
                                            app.filter.query = ip.to_string();
                                            app.flows_back_view = View::Overview;
                                            app.view = View::Flows;
                                            app.selected_row = 0;
                                            app.apply_filter();
                                            flow_state.select(Some(app.selected_row));
                                        }
                                        OverviewAction::FlowIndex(flow_i) => {
                                            app.flow_subset = None;
                                            app.subset_label = None;
                                            app.flows_back_view = View::Overview;
                                            app.view = View::Flows;
                                            app.apply_filter();
                                            if let Some(pos) = app
                                                .visible_flow_indices
                                                .iter()
                                                .position(|i| *i == flow_i)
                                            {
                                                app.selected_row = pos;
                                            } else {
                                                app.selected_row = 0;
                                            }
                                            flow_state.select(Some(app.selected_row));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    KeyCode::Char(c) if c.is_ascii_digit() => {
                        let n = c.to_digit(10).unwrap_or(0) as usize;
                        if n == 0 {
                            // ignore
                        } else if app.view == View::Weird {
                            // 1-based selection
                            app.weird_selected_row = n.saturating_sub(1);
                        } else if app.view == View::Domains {
                            app.domains_selected_row = n.saturating_sub(1);
                        } else if app.view == View::Overview {
                            app.overview_selected_row = n.saturating_sub(1);
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
                    KeyCode::PageDown => {
                        if app.view == View::Packets {
                            if let Some(fl) = app.selected_flow() {
                                let len = fl.packet_indices.len();
                                if len > 0 {
                                    let vp = app.packets_viewport_rows.max(1);
                                    let step = vp.saturating_sub(1).max(1);
                                    app.packets_selected_row =
                                        (app.packets_selected_row + step).min(len - 1);
                                    if app.packets_selected_row >= app.packets_scroll_row + vp {
                                        app.packets_scroll_row =
                                            app.packets_selected_row.saturating_sub(vp - 1);
                                    }
                                }
                            }
                        }
                    }
                    KeyCode::PageUp => {
                        if app.view == View::Packets {
                            let vp = app.packets_viewport_rows.max(1);
                            let step = vp.saturating_sub(1).max(1);
                            app.packets_selected_row =
                                app.packets_selected_row.saturating_sub(step);
                            if app.packets_selected_row < app.packets_scroll_row {
                                app.packets_scroll_row = app.packets_selected_row;
                            }
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => match app.view {
                        View::Overview => {
                            app.overview_selected_row = app.overview_selected_row.saturating_add(1);
                        }
                        View::Flows => {
                            app.move_down();
                            flow_state.select(Some(app.selected_row));
                        }
                        View::Weird => {
                            app.weird_selected_row = app.weird_selected_row.saturating_add(1);
                        }
                        View::Domains => {
                            app.domains_selected_row = app.domains_selected_row.saturating_add(1);
                        }
                        View::Packets => {
                            if let Some(fl) = app.selected_flow() {
                                let len = fl.packet_indices.len();
                                if len > 0 {
                                    app.packets_selected_row =
                                        (app.packets_selected_row + 1).min(len - 1);
                                    // keep selected row visible
                                    let vp = app.packets_viewport_rows.max(1);
                                    if app.packets_selected_row >= app.packets_scroll_row + vp {
                                        app.packets_scroll_row =
                                            app.packets_selected_row.saturating_sub(vp - 1);
                                    }
                                }
                            }
                        }
                        View::Stream => {
                            app.scroll_down();
                        }
                    },
                    KeyCode::Up | KeyCode::Char('k') => match app.view {
                        View::Overview => {
                            app.overview_selected_row = app.overview_selected_row.saturating_sub(1);
                        }
                        View::Flows => {
                            app.move_up();
                            flow_state.select(Some(app.selected_row));
                        }
                        View::Weird => {
                            app.weird_selected_row = app.weird_selected_row.saturating_sub(1);
                        }
                        View::Domains => {
                            app.domains_selected_row = app.domains_selected_row.saturating_sub(1);
                        }
                        View::Packets => {
                            if let Some(_fl) = app.selected_flow() {
                                app.packets_selected_row = app.packets_selected_row.saturating_sub(1);
                                let vp = app.packets_viewport_rows.max(1);
                                if app.packets_selected_row < app.packets_scroll_row {
                                    app.packets_scroll_row = app.packets_selected_row;
                                } else if app.packets_selected_row >= app.packets_scroll_row + vp {
                                    app.packets_scroll_row =
                                        app.packets_selected_row.saturating_sub(vp - 1);
                                }
                            }
                        }
                        View::Stream => {
                            app.scroll_up();
                        }
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
    fn compute_live_drop_is_saturating() {
        assert_eq!(App::compute_live_drop(10, 10), 0);
        assert_eq!(App::compute_live_drop(9, 10), 0);
        assert_eq!(App::compute_live_drop(11, 10), 1);
    }

    #[test]
    fn glossary_contains_core_terms() {
        let lines = build_glossary_lines();
        let all = lines
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(all.contains("SYN"));
        assert!(all.contains("NXDOMAIN"));
        assert!(all.contains("QUIC"));
    }

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
        let n = 300usize;
        let bytes = b"ab".repeat(n);
        let needle = b"ab";

        let small_cap = (STREAM_MATCH_HIGHLIGHT_CAP / 10).max(1);
        let small = crate::search::find_all_subslice_positions(&bytes, needle, small_cap);
        let big =
            crate::search::find_all_subslice_positions(&bytes, needle, STREAM_MATCH_HIGHLIGHT_CAP);

        assert_eq!(small.len(), small_cap.min(300));
        assert_eq!(big.len(), n);
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
        app.view = View::Stream;
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

    #[test]
    fn typing_in_stream_search_resets_scroll_and_clears_current_match() {
        let mut app = App::new(
            "/tmp/nope.pcap",
            Vec::new(),
            FlowIndex { flows: Vec::new() },
        );
        app.modal = Modal::StreamSearch;
        app.view = View::Stream;
        app.stream_scroll = 5;
        app.stream_last_match = Some(123);

        app.modal_push('a');

        assert_eq!(app.stream_scroll, 0);
        assert_eq!(app.stream_last_match, None);
    }

    #[test]
    fn backspace_in_stream_search_resets_scroll_and_clears_current_match() {
        let mut app = App::new(
            "/tmp/nope.pcap",
            Vec::new(),
            FlowIndex { flows: Vec::new() },
        );
        app.modal = Modal::StreamSearch;
        app.view = View::Stream;
        app.stream_scroll = 5;
        app.stream_last_match = Some(123);
        app.stream_search = "ab".to_string();

        app.modal_pop();

        assert_eq!(app.stream_scroll, 0);
        assert_eq!(app.stream_last_match, None);
    }

    #[test]
    fn refresh_stream_match_count_does_not_recurse_infinitely() {
        let mut app = App::new(
            "/tmp/nope.pcap",
            Vec::new(),
            FlowIndex { flows: Vec::new() },
        );
        app.view = View::Stream;
        // With no flows selected, this should be a no-op and must not overflow.
        app.refresh_stream_match_count();
    }

    #[test]
    fn refresh_stream_match_count_is_noop_without_selected_flow() {
        let mut app = App::new(
            "/tmp/nope.pcap",
            Vec::new(),
            FlowIndex { flows: Vec::new() },
        );
        app.view = View::Stream;
        app.stream_search.clear();
        app.stream_match_count = 99;
        app.refresh_stream_match_count();

        // With no selected flow, refresh_stream_match_count() should be a no-op.
        assert_eq!(app.stream_match_count, 99);
        assert!(matches!(app.view, View::Stream));
    }

    #[test]
    fn any_match_base_style_is_not_dimmed() {
        assert_ne!(
            style_any_match_base(),
            style_any_match_base().add_modifier(Modifier::DIM),
        );
    }

    #[test]
    fn search_modal_match_count_format_appends_plus_when_capped() {
        let match_count = STREAM_MATCH_HIGHLIGHT_CAP;
        let s = format!("{match_count}{}", match_cap_suffix(match_count));
        assert!(s.ends_with('+'));
    }

    #[test]
    fn match_cap_suffix_is_empty_below_cap() {
        assert_eq!(match_cap_suffix(STREAM_MATCH_HIGHLIGHT_CAP - 1), "");
    }

    #[test]
    fn tab_prev_is_noop_outside_stream_view() {
        let mut app = App::new(
            "/tmp/nope.pcap",
            Vec::new(),
            FlowIndex { flows: Vec::new() },
        );
        app.view = View::Flows;
        app.stream_tab = StreamTab::Combined;
        app.tab_prev();
        assert!(matches!(app.stream_tab, StreamTab::Combined));
    }

    #[test]
    fn tab_next_is_noop_outside_stream_view() {
        let mut app = App::new(
            "/tmp/nope.pcap",
            Vec::new(),
            FlowIndex { flows: Vec::new() },
        );
        app.view = View::Flows;
        app.stream_tab = StreamTab::Combined;
        app.tab_next();
        assert!(matches!(app.stream_tab, StreamTab::Combined));
    }
}

const STREAM_SEARCH_MODAL_TITLE: &str = "Stream search";
const STREAM_SEARCH_MODAL_HELP: &str =
    "Enter = apply   Esc = cancel   Ctrl+u = clear   (n/N next/prev, Tab/Shift-Tab switch stream)";
const STREAM_SEARCH_STATUS_TYPE_TO_SEARCH: &str = "type to search";
const STREAM_SEARCH_STATUS_MATCH_FOUND: &str = "match found (n/N to navigate)";
const STREAM_SEARCH_STATUS_NO_MATCHES: &str = "no matches";

fn build_explain_lines(app: &App) -> Vec<Line<'static>> {
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

fn render_explain_modal(
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

fn build_glossary_lines() -> Vec<Line<'static>> {
    let mut out: Vec<Line<'static>> = Vec::new();

    out.push(Line::from(Span::styled(
        "Glossary",
        Style::default().fg(c_accent()).add_modifier(Modifier::BOLD),
    )));
    out.push(Line::from(Span::raw("")));

    out.push(Line::from(Span::styled(
        "TCP flags",
        Style::default().fg(c_muted()).add_modifier(Modifier::BOLD),
    )));
    out.push(Line::from(vec![
        Span::styled("• SYN: ", Style::default().fg(c_muted())),
        Span::styled("Start a TCP connection.", Style::default().fg(c_text())),
    ]));
    out.push(Line::from(vec![
        Span::styled("• ACK: ", Style::default().fg(c_muted())),
        Span::styled("Acknowledges received bytes.", Style::default().fg(c_text())),
    ]));
    out.push(Line::from(vec![
        Span::styled("• FIN: ", Style::default().fg(c_muted())),
        Span::styled("Graceful close.", Style::default().fg(c_text())),
    ]));
    out.push(Line::from(vec![
        Span::styled("• RST: ", Style::default().fg(c_muted())),
        Span::styled("Abort / refused connection.", Style::default().fg(c_text())),
    ]));

    out.push(Line::from(Span::raw("")));
    out.push(Line::from(Span::styled(
        "DNS failure codes",
        Style::default().fg(c_muted()).add_modifier(Modifier::BOLD),
    )));
    out.push(Line::from(vec![
        Span::styled("• NXDOMAIN: ", Style::default().fg(c_muted())),
        Span::styled("Name does not exist.", Style::default().fg(c_text())),
    ]));
    out.push(Line::from(vec![
        Span::styled("• SERVFAIL: ", Style::default().fg(c_muted())),
        Span::styled("Resolver error.", Style::default().fg(c_text())),
    ]));

    out.push(Line::from(Span::raw("")));
    out.push(Line::from(Span::styled(
        "Protocols",
        Style::default().fg(c_muted()).add_modifier(Modifier::BOLD),
    )));
    out.push(Line::from(vec![
        Span::styled("• TCP: ", Style::default().fg(c_muted())),
        Span::styled(
            "Reliable, ordered stream (retransmits on loss).",
            Style::default().fg(c_text()),
        ),
    ]));
    out.push(Line::from(vec![
        Span::styled("• UDP: ", Style::default().fg(c_muted())),
        Span::styled(
            "Unreliable datagrams (no built-in retransmit).",
            Style::default().fg(c_text()),
        ),
    ]));
    out.push(Line::from(vec![
        Span::styled("• QUIC: ", Style::default().fg(c_muted())),
        Span::styled(
            "Reliable transport over UDP (used by HTTP/3).",
            Style::default().fg(c_text()),
        ),
    ]));

    out.push(Line::from(Span::raw("")));
    out.push(Line::from(Span::styled(
        "Streams",
        Style::default().fg(c_muted()).add_modifier(Modifier::BOLD),
    )));
    out.push(Line::from(vec![
        Span::styled("• Follow stream: ", Style::default().fg(c_muted())),
        Span::styled(
            "Reassembled payload bytes for a TCP flow direction (best-effort).",
            Style::default().fg(c_text()),
        ),
    ]));
    out.push(Line::from(vec![
        Span::styled("• TLS note: ", Style::default().fg(c_muted())),
        Span::styled(
            "HTTPS payload is encrypted; without keys you typically can’t inspect contents.",
            Style::default().fg(c_text()),
        ),
    ]));

    out.push(Line::from(Span::raw("")));
    out.push(Line::from(Span::styled(
        "Esc/Backspace to close",
        Style::default().fg(c_muted()),
    )));

    out
}

fn render_glossary_modal(
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

fn build_help_lines() -> Vec<Line<'static>> {
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
        Line::from(Span::styled(
            "Esc to close",
            Style::default().fg(c_muted()),
        )),
    ]
}

fn render_help_modal(
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
