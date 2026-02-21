use babyshark::pcap::{parse_cidr_list, read_pcap};

#[test]
fn parse_cidr_list_works() {
    let nets = parse_cidr_list("10.0.0.0/8, 192.168.0.0/16").unwrap();
    assert_eq!(nets.len(), 2);
}

#[test]
fn read_empty_pcap_is_ok() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    let _writer = pcap_file::pcap::PcapWriter::new(tmp.as_file_mut()).unwrap();

    let rows = read_pcap(tmp.path()).unwrap();
    assert!(rows.is_empty());
}
