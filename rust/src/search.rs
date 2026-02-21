/// Return the first index of `needle` in `haystack`, if any.
pub fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    find_subslice_from(haystack, needle, 0)
}

/// Return the first index of `needle` in `haystack` at or after `start`.
pub fn find_subslice_from(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() {
        return Some(start.min(haystack.len()));
    }
    if start >= haystack.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| start + p)
}

/// Convenience alias used by UI: next match at or after start.
pub fn find_next_subslice_from(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    find_subslice_from(haystack, needle, start)
}

/// Convenience alias used by UI: previous match strictly before end.
pub fn find_prev_subslice_before(haystack: &[u8], needle: &[u8], end: usize) -> Option<usize> {
    rfind_subslice_before(haystack, needle, end)
}

/// Find up to `max_matches` match start indices of `needle` in `haystack`.
///
/// Matches may overlap (e.g. "aaaa" + "aa" -> [0, 1, 2]).
pub fn find_all_subslice_positions(
    haystack: &[u8],
    needle: &[u8],
    max_matches: usize,
) -> Vec<usize> {
    if needle.is_empty() || max_matches == 0 {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut start = 0usize;
    while start <= haystack.len() {
        if out.len() >= max_matches {
            break;
        }
        let Some(pos) = find_subslice_from(haystack, needle, start) else {
            break;
        };
        out.push(pos);
        // Allow overlaps by advancing only one byte.
        start = pos.saturating_add(1);
    }
    out
}

/// Return the last index of `needle` in `haystack` strictly before `end`.
pub fn rfind_subslice_before(haystack: &[u8], needle: &[u8], end: usize) -> Option<usize> {
    if needle.is_empty() {
        return Some(end.min(haystack.len()));
    }
    let end = end.min(haystack.len());
    if end < needle.len() {
        return None;
    }
    haystack[..end]
        .windows(needle.len())
        .rposition(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_subslice() {
        assert_eq!(find_subslice(b"hello world", b"world"), Some(6));
        assert_eq!(find_subslice(b"aaaa", b"aa"), Some(0));
        assert_eq!(find_subslice(b"abcd", b""), Some(0));
        assert_eq!(find_subslice(b"abcd", b"zzz"), None);
    }

    #[test]
    fn finds_from() {
        assert_eq!(find_subslice_from(b"abcabc", b"abc", 0), Some(0));
        assert_eq!(find_subslice_from(b"abcabc", b"abc", 1), Some(3));
        assert_eq!(find_subslice_from(b"abcabc", b"abc", 4), None);
    }

    #[test]
    fn rfind_before() {
        assert_eq!(rfind_subslice_before(b"abcabc", b"abc", 6), Some(3));
        assert_eq!(rfind_subslice_before(b"abcabc", b"abc", 3), Some(0));
        assert_eq!(rfind_subslice_before(b"abcabc", b"abc", 2), None);
    }

    #[test]
    fn find_all_positions_overlapping() {
        assert_eq!(
            find_all_subslice_positions(b"aaaa", b"aa", 10),
            vec![0, 1, 2]
        );
        assert_eq!(
            find_all_subslice_positions(b"abcabc", b"abc", 10),
            vec![0, 3]
        );
        assert_eq!(
            find_all_subslice_positions(b"abc", b"", 10),
            Vec::<usize>::new()
        );
        assert_eq!(
            find_all_subslice_positions(b"abc", b"z", 10),
            Vec::<usize>::new()
        );
        assert_eq!(find_all_subslice_positions(b"aaaa", b"aa", 2), vec![0, 1]);
    }
}
