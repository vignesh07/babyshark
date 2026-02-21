/// Return the first index of `needle` in `haystack`, if any.
pub fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
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
}
