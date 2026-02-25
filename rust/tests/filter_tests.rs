use babyshark::flow::{DirStats, FlowStats};
use babyshark::pcap::{FlowKey, L4Proto};
use babyshark::ui_filter::FlowFilter;
use std::net::IpAddr;

fn mk_flow(proto: L4Proto) -> FlowStats {
    FlowStats {
        key: FlowKey {
            src: IpAddr::from([10, 0, 0, 1]),
            dst: IpAddr::from([10, 0, 0, 2]),
            src_port: 1234,
            dst_port: 80,
            proto,
        },
        total_packets: 2,
        total_bytes: 20,
        a_to_b: DirStats {
            packets: 1,
            bytes: 10,
        },
        b_to_a: DirStats {
            packets: 1,
            bytes: 10,
        },
        packet_indices: vec![0, 1],
        analysis: None,
    }
}

#[test]
fn filter_query_matches_endpoints() {
    let f = mk_flow(L4Proto::Tcp);
    let mut flt = FlowFilter::default();
    flt.query = "10.0.0.1".into();
    assert!(flt.matches(&f));
    flt.query = "9999".into();
    assert!(!flt.matches(&f));
}

#[test]
fn filter_proto_toggles_work() {
    let tcp = mk_flow(L4Proto::Tcp);
    let udp = mk_flow(L4Proto::Udp);
    let mut flt = FlowFilter::default();

    flt.show_tcp = true;
    flt.show_udp = false;
    assert!(flt.matches(&tcp));
    assert!(!flt.matches(&udp));

    flt.show_tcp = false;
    flt.show_udp = true;
    assert!(!flt.matches(&tcp));
    assert!(flt.matches(&udp));
}
