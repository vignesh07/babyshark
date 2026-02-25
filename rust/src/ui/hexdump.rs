use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};

use super::{c_accent, c_muted, c_text};

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

pub(super) fn ascii_cell(b: u8) -> &'static str {
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

pub(super) const HEXDUMP_OFFSET_LUT_MAX: usize = 0xFFFF;
// Placeholder shown when the offset exceeds the cached LUT range.
// (Fixed width to preserve column alignment.)
pub(super) const HEXDUMP_OFFSET_TOO_LARGE: &str = "0x??????  ";

/// Format a hexdump offset as an owned string.
///
/// Used for lookup table initialization.
fn fmt_hexdump_offset_owned(offset: usize) -> Box<str> {
    format!("0x{:>6x}  ", offset).into_boxed_str()
}

/// Format a hexdump offset for display.
///
/// Fast path: cached strings for offsets up to `HEXDUMP_OFFSET_LUT_MAX`.
pub(super) fn fmt_hexdump_offset(offset: usize) -> &'static str {
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
pub(super) const UI_ONE_SPACE: &str = " ";
pub(super) const UI_SPACER: &str = "  ";
pub(super) const STREAM_MATCH_HIGHLIGHT_CAP: usize = 2000;

pub(super) fn match_cap_suffix(count: usize) -> &'static str {
    if count >= STREAM_MATCH_HIGHLIGHT_CAP {
        "+"
    } else {
        ""
    }
}

pub(super) fn match_ordinal(match_positions: &[usize], current: Option<usize>) -> Option<usize> {
    let cur = current?;
    match_positions.iter().position(|p| *p == cur)
}

pub(super) fn scroll_for_match_pos(pos: usize) -> u16 {
    (pos / HEXDUMP_COLS) as u16
}

pub(super) fn byte_in_any_range(abs: usize, ranges: &[(usize, usize)]) -> bool {
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

pub(super) fn style_current_match() -> Style {
    Style::default()
        .fg(Color::Black)
        .bg(c_accent())
        .add_modifier(Modifier::BOLD)
}

pub(super) fn style_any_match_base() -> Style {
    Style::default().fg(Color::Black).bg(c_accent())
}

pub(super) fn style_any_match() -> Style {
    style_any_match_base().add_modifier(Modifier::DIM)
}

pub(super) fn first_match_and_scroll(bytes: &[u8], needle: &[u8]) -> Option<(usize, u16)> {
    if needle.is_empty() {
        return None;
    }
    let pos = crate::search::find_subslice(bytes, needle)?;
    let scroll = scroll_for_match_pos(pos);
    Some((pos, scroll))
}

pub(super) fn next_match_and_scroll(
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

pub(super) fn prev_match_and_scroll(
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

pub(super) fn bytes_to_pretty_lines(
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

pub(super) fn bytes_to_pretty_text(
    bytes: &[u8],
    match_ranges: &[(usize, usize)],
    current_match: Option<(usize, usize)>,
) -> Text<'static> {
    Text::from(bytes_to_pretty_lines(bytes, match_ranges, current_match))
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
    fn match_cap_suffix_is_empty_below_cap() {
        assert_eq!(match_cap_suffix(STREAM_MATCH_HIGHLIGHT_CAP - 1), "");
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
}
