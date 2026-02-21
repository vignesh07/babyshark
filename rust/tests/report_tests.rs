use babyshark::flow::FlowIndex;
use babyshark::pcap::read_pcap;
use babyshark::report::{write_report_md, ReportOptions};
use babyshark::ui_filter::FlowFilter;

mod fixtures;

#[test]
fn report_writes_markdown() {
    let dir = tempfile::tempdir().unwrap();
    let pcap = dir.path().join("x.pcap");
    {
        let mut f = std::fs::File::create(&pcap).unwrap();
        fixtures::write_two_tcp_packets(&mut f);
    }

    let rows = read_pcap(&pcap).unwrap();
    let flows = FlowIndex::build(&rows);
    let filter = FlowFilter::default();

    let out = dir.path().join("report.md");
    write_report_md(
        &out,
        &pcap,
        &rows,
        &flows,
        &filter,
        &[],
        flows.flows.get(0),
        ReportOptions {
            max_flows: 10,
            max_stream_bytes: 64,
        },
    )
    .unwrap();

    let s = std::fs::read_to_string(&out).unwrap();
    assert!(s.contains("# babyshark report"));
    assert!(s.contains("## Flows"));
    assert!(s.contains("Selected flow"));
}
