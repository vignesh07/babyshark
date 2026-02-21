mod fixtures;

use babyshark::flow::FlowIndex;
use babyshark::pcap::{read_pcap, L4Proto};

#[test]
fn flow_index_groups_bidirectional() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    fixtures::write_two_tcp_packets(tmp.as_file_mut());

    let rows = read_pcap(tmp.path()).unwrap();
    assert_eq!(rows.len(), 2);

    // sanity: both are TCP
    assert!(rows.iter().all(|r| r.proto == Some(L4Proto::Tcp)));

    let idx = FlowIndex::build(&rows);
    assert_eq!(idx.flows.len(), 1);

    let f = &idx.flows[0];
    assert_eq!(f.total_packets, 2);
    assert_eq!(f.a_to_b.packets + f.b_to_a.packets, 2);
    assert_eq!(f.packet_indices, vec![0, 1]);
}
