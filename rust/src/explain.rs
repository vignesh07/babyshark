use crate::flow::FlowStats;
use crate::pcap::{L4Proto, PacketRow};

#[derive(Debug, Clone, Default)]
pub struct ExplainSummary {
    pub title: String,
    pub likely: String,
    pub why: Vec<String>,
    pub next: Vec<String>,
}

pub fn explain_flow(rows: &[PacketRow], fl: &FlowStats) -> ExplainSummary {
    let (service, why, next) = classify_flow(rows, fl);

    ExplainSummary {
        title: fl.label(),
        likely: service,
        why,
        next,
    }
}

fn classify_flow(rows: &[PacketRow], fl: &FlowStats) -> (String, Vec<String>, Vec<String>) {
    let mut why: Vec<String> = Vec::new();
    let mut next: Vec<String> = Vec::new();

    let p = match fl.key.proto {
        L4Proto::Tcp => "TCP",
        L4Proto::Udp => "UDP",
        L4Proto::Other(_) => "L4",
    };

    // Simple service guesses by port.
    let port = fl.key.dst_port.min(fl.key.src_port);
    let mut service = match (fl.key.proto, port) {
        (L4Proto::Udp, 53) => "DNS".to_string(),
        (L4Proto::Udp, 5353) => "mDNS (local discovery noise)".to_string(),
        (L4Proto::Udp, 1900) => "SSDP/UPnP (local discovery noise)".to_string(),
        (L4Proto::Tcp, 80) => "HTTP".to_string(),
        (L4Proto::Tcp, 443) => "HTTPS/TLS".to_string(),
        (L4Proto::Tcp, 22) => "SSH".to_string(),
        _ => format!("{p} traffic"),
    };

    // Signals from packets
    let mut rst = 0u64;
    let mut syn = 0u64;
    let mut syn_ack = 0u64;
    let mut dns_names: Vec<String> = Vec::new();
    let mut http_hosts: Vec<String> = Vec::new();
    let mut tls_sni: Vec<String> = Vec::new();

    for idx in fl.packet_indices.iter().copied() {
        let Some(r) = rows.get(idx) else { continue };
        if let Some(flags) = r.tcp_flags {
            if (flags & 0x04) != 0 {
                rst += 1;
            }
            if (flags & 0x02) != 0 && (flags & 0x10) == 0 {
                syn += 1;
            }
            if (flags & 0x02) != 0 && (flags & 0x10) != 0 {
                syn_ack += 1;
            }
        }
        if let Some(n) = &r.dns_qname {
            if dns_names.len() < 3 && !dns_names.contains(n) {
                dns_names.push(n.clone());
            }
        }
        if let Some(h) = &r.http_host {
            if http_hosts.len() < 3 && !http_hosts.contains(h) {
                http_hosts.push(h.clone());
            }
        }
        if let Some(s) = &r.tls_sni {
            if tls_sni.len() < 3 && !tls_sni.contains(s) {
                tls_sni.push(s.clone());
            }
        }
    }

    if rst > 0 {
        why.push(format!("Saw {rst} TCP reset(s) (RST)"));
        next.push("Open Weird stuff (W) to see other failing flows".to_string());
    }

    if fl.key.proto == L4Proto::Tcp && syn >= 2 && syn_ack == 0 {
        why.push(
            "Repeated SYNs but no SYN,ACK (could be blocked or capture is one-sided)".to_string(),
        );
        next.push("Check if you captured both directions (same interface?)".to_string());
    }

    if !dns_names.is_empty() {
        service = "DNS".to_string();
        why.push(format!("DNS names seen: {}", dns_names.join(", ")));
        next.push("Open Domains (D) to pivot by hostname".to_string());
    }

    if !http_hosts.is_empty() {
        service = "HTTP".to_string();
        why.push(format!("HTTP Host: {}", http_hosts.join(", ")));
        next.push("Follow stream (f) to see the request/response".to_string());
    }

    if !tls_sni.is_empty() {
        service = "HTTPS/TLS".to_string();
        why.push(format!("TLS SNI: {}", tls_sni.join(", ")));
        next.push("Open Domains (D) to pivot by hostname".to_string());
    }

    // Set expectations about encrypted payloads.
    if service.contains("TLS") {
        next.push(
            "Note: TLS payload is encrypted; without keys you can’t inspect the contents — but timing, sizes, resets/retries, and host hints still help.".to_string(),
        );
    }

    if next.is_empty() {
        next.push("From packets: press f to Follow stream (TCP)".to_string());
        next.push("Use / to search in the stream".to_string());
    }

    (service, why, next)
}
