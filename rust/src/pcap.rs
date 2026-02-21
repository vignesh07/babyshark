use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use ipnet::IpNet;
use pcap_file::pcap::{PcapPacket, PcapReader};
use pcap_file::pcapng::PcapNgReader;
use std::fs::File;
use std::io::{BufReader, Read, Seek};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum L4Proto {
    Tcp,
    Udp,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowDir {
    AtoB,
    BtoA,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: L4Proto,
}

impl FlowKey {
    /// Canonicalize direction so A→B and B→A collapse into one conversation key.
    pub fn canonical(&self) -> (FlowKey, bool) {
        // Return (canonical_key, flipped)
        let left = (self.src, self.src_port);
        let right = (self.dst, self.dst_port);
        if left < right {
            (self.clone(), false)
        } else if left > right {
            (
                FlowKey {
                    src: self.dst,
                    dst: self.src,
                    src_port: self.dst_port,
                    dst_port: self.src_port,
                    proto: self.proto,
                },
                true,
            )
        } else {
            // identical endpoints (loopback oddity); keep as-is
            (self.clone(), false)
        }
    }
}

#[derive(Debug, Clone)]
pub struct PacketRow {
    pub index: usize,
    pub ts: DateTime<Utc>,
    pub len: usize,
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
    pub proto: Option<L4Proto>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub summary: String,
    pub flow: Option<FlowKey>,
    pub flow_dir: Option<FlowDir>,
    pub payload: Vec<u8>,
}

fn ts_from_duration(d: std::time::Duration) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(d.as_secs() as i64, d.subsec_nanos()).unwrap_or_else(|| {
        DateTime::<Utc>::from_timestamp(0, 0).unwrap()
    })
}

fn decode_packet(index: usize, ts: DateTime<Utc>, data: &[u8]) -> PacketRow {
    // We only decode L3/L4. If no Ethernet header (e.g. raw IP), SlicedPacket can still parse.
    let mut row = PacketRow {
        index,
        ts,
        len: data.len(),
        src: None,
        dst: None,
        proto: None,
        src_port: None,
        dst_port: None,
        summary: String::new(),
        flow: None,
        flow_dir: None,
        payload: Vec::new(),
    };

    if let Ok(sliced) = SlicedPacket::from_ethernet(data) {
        if let Some(net) = sliced.net {
            match net {
                NetSlice::Ipv4(ipv4) => {
                    row.src = Some(IpAddr::V4(Ipv4Addr::from(ipv4.header().source())));
                    row.dst = Some(IpAddr::V4(Ipv4Addr::from(ipv4.header().destination())));
                }
                NetSlice::Ipv6(ipv6) => {
                    row.src = Some(IpAddr::V6(Ipv6Addr::from(ipv6.header().source())));
                    row.dst = Some(IpAddr::V6(Ipv6Addr::from(ipv6.header().destination())));
                }
            }
        }

        if let Some(transport) = sliced.transport {
            match transport {
                TransportSlice::Tcp(tcp) => {
                    row.proto = Some(L4Proto::Tcp);
                    row.src_port = Some(tcp.source_port());
                    row.dst_port = Some(tcp.destination_port());
                    row.payload = tcp.payload().to_vec();
                }
                TransportSlice::Udp(udp) => {
                    row.proto = Some(L4Proto::Udp);
                    row.src_port = Some(udp.source_port());
                    row.dst_port = Some(udp.destination_port());
                    row.payload = udp.payload().to_vec();
                }
                _ => {}
            }
        }

        if let (Some(src), Some(dst), Some(proto), Some(sp), Some(dp)) =
            (row.src, row.dst, row.proto, row.src_port, row.dst_port)
        {
            let fk = FlowKey {
                src,
                dst,
                src_port: sp,
                dst_port: dp,
                proto,
            };
            let (_canon, flipped) = fk.canonical();
            row.flow_dir = Some(if flipped { FlowDir::BtoA } else { FlowDir::AtoB });
            row.flow = Some(fk);
        }

        row.summary = summarize(&row);
        return row;
    }

    // try raw IP parse
    if let Ok(sliced) = SlicedPacket::from_ip(data) {
        if let Some(net) = sliced.net {
            match net {
                NetSlice::Ipv4(ipv4) => {
                    row.src = Some(IpAddr::V4(Ipv4Addr::from(ipv4.header().source())));
                    row.dst = Some(IpAddr::V4(Ipv4Addr::from(ipv4.header().destination())));
                }
                NetSlice::Ipv6(ipv6) => {
                    row.src = Some(IpAddr::V6(Ipv6Addr::from(ipv6.header().source())));
                    row.dst = Some(IpAddr::V6(Ipv6Addr::from(ipv6.header().destination())));
                }
            }
        }
        if let Some(transport) = sliced.transport {
            match transport {
                TransportSlice::Tcp(tcp) => {
                    row.proto = Some(L4Proto::Tcp);
                    row.src_port = Some(tcp.source_port());
                    row.dst_port = Some(tcp.destination_port());
                    row.payload = tcp.payload().to_vec();
                }
                TransportSlice::Udp(udp) => {
                    row.proto = Some(L4Proto::Udp);
                    row.src_port = Some(udp.source_port());
                    row.dst_port = Some(udp.destination_port());
                    row.payload = udp.payload().to_vec();
                }
                _ => {}
            }
        }

        if let (Some(src), Some(dst), Some(proto), Some(sp), Some(dp)) =
            (row.src, row.dst, row.proto, row.src_port, row.dst_port)
        {
            let fk = FlowKey {
                src,
                dst,
                src_port: sp,
                dst_port: dp,
                proto,
            };
            let (_canon, flipped) = fk.canonical();
            row.flow_dir = Some(if flipped { FlowDir::BtoA } else { FlowDir::AtoB });
            row.flow = Some(fk);
        }

        row.summary = summarize(&row);
        return row;
    }

    row.summary = format!("len={} (undecoded)", row.len);
    row
}

fn summarize(row: &PacketRow) -> String {
    match (row.src, row.dst, row.proto, row.src_port, row.dst_port) {
        (Some(src), Some(dst), Some(L4Proto::Tcp), Some(sp), Some(dp)) => {
            let payload = if row.payload.is_empty() { "" } else { " payload" };
            format!("TCP {src}:{sp} → {dst}:{dp}{payload}")
        }
        (Some(src), Some(dst), Some(L4Proto::Udp), Some(sp), Some(dp)) => {
            format!("UDP {src}:{sp} → {dst}:{dp} len={}", row.len)
        }
        (Some(src), Some(dst), Some(proto), _, _) => format!("{proto:?} {src} → {dst} len={}", row.len),
        _ => format!("len={}", row.len),
    }
}

pub fn read_pcap(path: impl AsRef<Path>) -> Result<Vec<PacketRow>> {
    let path = path.as_ref();

    // Quick sniff by magic.
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)
        .with_context(|| format!("read magic {}", path.display()))?;
    f.rewind().ok();

    // PCAPNG magic: 0x0A0D0D0A at start
    if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
        return read_pcapng(path);
    }

    // Otherwise try classic pcap.
    read_pcap_classic(path)
}

fn read_pcap_classic(path: &Path) -> Result<Vec<PacketRow>> {
    let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut reader = PcapReader::new(BufReader::new(f)).with_context(|| "pcap reader")?;

    let mut out = Vec::new();
    let mut i = 0usize;

    while let Some(pkt) = reader.next_packet() {
        let pkt: PcapPacket = pkt.with_context(|| "read packet")?;
        let ts = ts_from_duration(pkt.timestamp);
        out.push(decode_packet(i, ts, &pkt.data));
        i += 1;
    }

    Ok(out)
}

fn read_pcapng(path: &Path) -> Result<Vec<PacketRow>> {
    let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut reader = PcapNgReader::new(BufReader::new(f)).with_context(|| "pcapng reader")?;

    let mut out = Vec::new();
    let mut i = 0usize;

    while let Some(block) = reader.next_block() {
        let block = block.with_context(|| "read pcapng block")?;
        match block {
            pcap_file::pcapng::blocks::Block::EnhancedPacket(epb) => {
                // Timestamp units come from interface description. pcap-file normalizes to raw value.
                // We'll best-effort treat epb.timestamp as microseconds since epoch if present.
                let ts = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
                out.push(decode_packet(i, ts, &epb.data));
                i += 1;
            }
            _ => {}
        }
    }

    Ok(out)
}

/// Utility: check if an IP is within any provided CIDR blocks.
pub fn ip_in_nets(ip: IpAddr, nets: &[IpNet]) -> bool {
    nets.iter().any(|n| n.contains(&ip))
}

pub fn parse_cidr_list(s: &str) -> Result<Vec<IpNet>> {
    let mut out = Vec::new();
    for part in s.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
        out.push(part.parse::<IpNet>().map_err(|e| anyhow!(e))?);
    }
    Ok(out)
}
