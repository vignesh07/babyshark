use babyshark::search::{find_subslice, find_subslice_from, rfind_subslice_before};

#[test]
fn find_subslice_basic() {
    assert_eq!(find_subslice(b"abcabc", b"cab"), Some(2));
}

#[test]
fn next_prev_helpers() {
    let h = b"aaaa";
    let n = b"aa";
    assert_eq!(find_subslice_from(h, n, 0), Some(0));
    assert_eq!(find_subslice_from(h, n, 1), Some(1));
    assert_eq!(find_subslice_from(h, n, 3), None);
    assert_eq!(rfind_subslice_before(h, n, 4), Some(2));
    assert_eq!(rfind_subslice_before(h, n, 2), Some(0));
}
