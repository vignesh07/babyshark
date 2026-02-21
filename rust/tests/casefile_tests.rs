use babyshark::casefile::{case_dir_for_pcap, case_path_for_pcap, CaseFile};
use std::path::Path;

#[test]
fn case_paths_are_in_hidden_dir() {
    let p = Path::new("/tmp/capture.pcap");
    let d = case_dir_for_pcap(p);
    let f = case_path_for_pcap(p);
    assert!(d.ends_with(".babyshark"));
    assert!(f.ends_with(".babyshark/case.json"));
}

#[test]
fn casefile_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let pcap = dir.path().join("x.pcap");
    std::fs::write(&pcap, b"").unwrap();

    let mut cf = CaseFile::load_or_new(&pcap).unwrap();
    cf.upsert_bookmark("k1", "TCP a↔b", "note1");
    cf.save(&pcap).unwrap();

    let cf2 = CaseFile::load_or_new(&pcap).unwrap();
    assert_eq!(cf2.bookmarks.len(), 1);
    assert_eq!(cf2.bookmarks[0].flow_key, "k1");
}
