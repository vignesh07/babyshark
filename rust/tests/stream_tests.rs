mod fixtures;

use babyshark::flow::FlowIndex;
use babyshark::pcap::read_pcap;
use babyshark::stream::build_stream;

#[test]
fn build_stream_concatenates_payloads_by_direction() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    fixtures::write_two_tcp_packets(tmp.as_file_mut());

    let rows = read_pcap(tmp.path()).unwrap();
    let idx = FlowIndex::build(&rows);
    let flow = &idx.flows[0];

    let s = build_stream(&rows, flow);
    assert_eq!(String::from_utf8_lossy(&s.a_to_b), "GET");
    assert_eq!(String::from_utf8_lossy(&s.b_to_a), "OK");
}

#[test]
fn build_stream_reassembles_out_of_order_tcp() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    fixtures::write_out_of_order_tcp(tmp.as_file_mut());

    let rows = read_pcap(tmp.path()).unwrap();
    let idx = FlowIndex::build(&rows);
    let flow = &idx.flows[0];

    let s = build_stream(&rows, flow);
    assert_eq!(String::from_utf8_lossy(&s.a_to_b), "HELLO");
}
