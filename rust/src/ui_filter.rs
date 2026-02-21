use crate::flow::FlowStats;
use crate::pcap::L4Proto;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowFilter {
    pub query: String,
    pub show_tcp: bool,
    pub show_udp: bool,
}

impl Default for FlowFilter {
    fn default() -> Self {
        FlowFilter {
            query: String::new(),
            show_tcp: true,
            show_udp: true,
        }
    }
}

impl FlowFilter {
    pub fn matches(&self, f: &FlowStats) -> bool {
        let proto_ok = match f.key.proto {
            L4Proto::Tcp => self.show_tcp,
            L4Proto::Udp => self.show_udp,
            L4Proto::Other(_) => true,
        };
        if !proto_ok {
            return false;
        }
        let q = self.query.trim().to_lowercase();
        if q.is_empty() {
            return true;
        }
        let hay = format!(
            "{} {}:{} {}:{}",
            match f.key.proto {
                L4Proto::Tcp => "tcp",
                L4Proto::Udp => "udp",
                L4Proto::Other(_) => "l4",
            },
            f.key.src,
            f.key.src_port,
            f.key.dst,
            f.key.dst_port
        )
        .to_lowercase();
        hay.contains(&q)
    }
}
