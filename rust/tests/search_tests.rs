use babyshark::search::find_subslice;

#[test]
fn find_subslice_basic() {
    assert_eq!(find_subslice(b"abcabc", b"cab"), Some(2));
}
