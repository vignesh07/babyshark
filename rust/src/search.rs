/// Return the first index of `needle` in `haystack`, if any.
pub fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    find_next_subslice_from(haystack, needle, 0)
}

/// Return the first index of `needle` in `haystack`, searching starting at `from`.
///
/// If `needle` is empty, returns `Some(from.min(haystack.len()))`.
pub fn find_next_subslice_from(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    let from = from.min(haystack.len());
    if needle.is_empty() {
        return Some(from);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| from + i)
}

/// Return the last index of `needle` in `haystack` whose start is `< before`.
///
/// If `needle` is empty, returns `Some(before.min(haystack.len()))`.
pub fn find_prev_subslice_before(haystack: &[u8], needle: &[u8], before: usize) -> Option<usize> {
    let before = before.min(haystack.len());
    if needle.is_empty() {
        return Some(before);
    }
    if needle.len() > haystack.len() {
        return None;
    }

    // We want match starts < before.
    let end = before;
    let search = &haystack[..end];
    search
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
    fn finds_next_from() {
        assert_eq!(find_next_subslice_from(b"aaaa", b"aa", 0), Some(0));
        assert_eq!(find_next_subslice_from(b"aaaa", b"aa", 1), Some(1));
        assert_eq!(find_next_subslice_from(b"aaaa", b"aa", 3), None);
        assert_eq!(find_next_subslice_from(b"abcd", b"", 2), Some(2));
        assert_eq!(find_next_subslice_from(b"abcd", b"", 999), Some(4));
    }

    #[test]
    fn finds_prev_before() {
        assert_eq!(find_prev_subslice_before(b"aaaa", b"aa", 4), Some(2));
        assert_eq!(find_prev_subslice_before(b"aaaa", b"aa", 3), Some(1));
        assert_eq!(find_prev_subslice_before(b"aaaa", b"aa", 1), None);
        assert_eq!(find_prev_subslice_before(b"abcd", b"", 2), Some(2));
        assert_eq!(find_prev_subslice_before(b"abcd", b"", 999), Some(4));
    }
}
