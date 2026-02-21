use etherparse::PacketBuilder;
use pcap_file::pcap::{PcapPacket, PcapWriter};
use std::time::Duration;

pub fn write_two_tcp_packets(mut w: impl std::io::Write) {
    let mut writer = PcapWriter::new(&mut w).unwrap();

    // Packet 0: 10.0.0.1:1234 -> 10.0.0.2:80 with payload "GET"
    let payload0 = b"GET";
    let mut pkt0 = Vec::with_capacity(128);
    PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .tcp(1234, 80, 1, 0)
        .write(&mut pkt0, payload0)
        .unwrap();

    // Packet 1: 10.0.0.2:80 -> 10.0.0.1:1234 with payload "OK"
    let payload1 = b"OK";
    let mut pkt1 = Vec::with_capacity(128);
    PacketBuilder::ethernet2([7, 8, 9, 10, 11, 12], [1, 2, 3, 4, 5, 6])
        .ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64)
        .tcp(80, 1234, 1, 0)
        .write(&mut pkt1, payload1)
        .unwrap();

    let p0 = PcapPacket::new(Duration::from_secs(1), pkt0.len() as u32, &pkt0);
    let p1 = PcapPacket::new(Duration::from_secs(2), pkt1.len() as u32, &pkt1);

    writer.write_packet(&p0).unwrap();
    writer.write_packet(&p1).unwrap();
}

/// Writes 2 A->B TCP segments out-of-order that should reassemble to "HELLO".
pub fn write_out_of_order_tcp(mut w: impl std::io::Write) {
    let mut writer = PcapWriter::new(&mut w).unwrap();

    // Segment 1: seq=3 payload="LLO"
    let mut pkt1 = Vec::with_capacity(128);
    PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .tcp(1234, 80, 3, 0)
        .write(&mut pkt1, b"LLO")
        .unwrap();

    // Segment 0: seq=1 payload="HE"
    let mut pkt0 = Vec::with_capacity(128);
    PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .tcp(1234, 80, 1, 0)
        .write(&mut pkt0, b"HE")
        .unwrap();

    let p1 = PcapPacket::new(Duration::from_secs(1), pkt1.len() as u32, &pkt1);
    let p0 = PcapPacket::new(Duration::from_secs(2), pkt0.len() as u32, &pkt0);

    // Write out of order (LLO first, HE second)
    writer.write_packet(&p1).unwrap();
    writer.write_packet(&p0).unwrap();
}
