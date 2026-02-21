mod fixtures {
    include!("../tests/fixtures/mod.rs");
}

fn main() {
    let mut buf: Vec<u8> = Vec::new();
    fixtures::write_two_tcp_packets(&mut buf);
    std::fs::write("rust/examples/two_tcp.pcap", buf).unwrap();
}
