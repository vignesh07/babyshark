use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;

use crate::pcap::{FlowDir, FlowKey, L4Proto, PacketRow};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfaceEntry {
    pub index: usize,
    pub name: String,
    pub desc: Option<String>,
}

pub fn parse_tshark_version_output(stdout: &str) -> Option<String> {
    // Example: "TShark (Wireshark) 4.2.4"
    stdout
        .lines()
        .map(|l| l.trim())
        .find(|l| !l.is_empty())
        .map(|l| l.to_string())
}

pub fn tshark_version() -> Result<String> {
    let out = Command::new("tshark")
        .arg("-v")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("failed to execute tshark -v")?;

    if !out.status.success() {
        return Err(anyhow!(
            "tshark -v failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_tshark_version_output(&stdout).ok_or_else(|| anyhow!("tshark -v produced no output"))
}

pub fn parse_tshark_ifaces_output(stdout: &str) -> Vec<IfaceEntry> {
    // Example lines:
    // 1. en0
    // 5. wlp0s20f3 (Wi-Fi)
    // 12. lo (Loopback)
    let mut out: Vec<IfaceEntry> = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let Some((idx_str, rest)) = line.split_once('.') else {
            continue;
        };
        let idx: usize = idx_str.trim().parse().ok().unwrap_or(0);
        let rest = rest.trim();
        if rest.is_empty() {
            continue;
        }

        let (name, desc) = if let Some((name, desc)) = rest.split_once(' ') {
            let desc = desc.trim();
            let desc = desc.strip_prefix('(').unwrap_or(desc);
            let desc = desc.strip_suffix(')').unwrap_or(desc);
            let desc = desc.trim();
            if desc.is_empty() {
                (name.to_string(), None)
            } else {
                (name.to_string(), Some(desc.to_string()))
            }
        } else {
            (rest.to_string(), None)
        };

        if idx == 0 {
            continue;
        }

        out.push(IfaceEntry {
            index: idx,
            name,
            desc,
        });
    }

    out
}

pub fn tshark_list_ifaces() -> Result<Vec<IfaceEntry>> {
    let out = Command::new("tshark")
        .arg("-D")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("failed to execute tshark -D")?;

    if !out.status.success() {
        return Err(anyhow!(
            "tshark -D failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    Ok(parse_tshark_ifaces_output(&stdout))
}

fn epoch_to_ts(epoch: f64) -> DateTime<Utc> {
    let secs = epoch.floor() as i64;
    let nanos = ((epoch - (secs as f64)) * 1e9).round() as u32;
    DateTime::<Utc>::from_timestamp(secs, nanos)
        .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).unwrap())
}

fn friendly_live_capture_error(stderr: &str) -> Option<String> {
    let s = stderr.to_lowercase();

    // Common permission problems across platforms.
    if s.contains("permission denied")
        || s.contains("operation not permitted")
        || s.contains("you don't have permission")
        || s.contains("could not open capture device")
        || s.contains("cap_net_raw")
        || s.contains("cap_net_admin")
    {
        return Some(
            "tshark failed to start live capture (likely permissions). Try: run with sudo, or install Wireshark/tshark with capture permissions (dumpcap).".to_string(),
        );
    }

    if s.contains("no such device") || s.contains("unknown device") {
        return Some(
            "unknown capture interface. Run with --list-ifaces to see available interfaces."
                .to_string(),
        );
    }

    None
}

pub fn tshark_live_preflight(iface: &str) -> Result<()> {
    // Attempt a very small capture to surface permission/config errors early.
    let out = Command::new("tshark")
        .args([
            "-n",
            "-i",
            iface,
            "-c",
            "1",
            "-a",
            "duration:1",
            "-T",
            "fields",
            "-E",
            "separator=	",
            "-E",
            "occurrence=f",
            "-E",
            "header=n",
            "-e",
            "frame.time_epoch",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("failed to execute tshark for live capture preflight")?;

    if out.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&out.stderr);
    if let Some(msg) = friendly_live_capture_error(&stderr) {
        return Err(anyhow!(
            "{msg}

Raw tshark error:
{stderr}"
        ));
    }

    Err(anyhow!(
        "tshark live capture preflight failed:
{}",
        stderr.trim()
    ))
}
/// Parse a single `tshark -T fields` line (tab-separated), best-effort.
///
/// Field order (see `spawn_live_capture_tshark_fields`):
/// frame.time_epoch, frame.len,
/// ip.src, ip.dst, ipv6.src, ipv6.dst,
/// tcp.srcport, tcp.dstport, udp.srcport, udp.dstport,
/// _ws.col.Protocol,
/// tcp.flags
pub fn parse_tshark_fields_line(line: &str) -> Option<PacketRow> {
    let parts: Vec<&str> = line
        .trim_end_matches(&['\n', '\r'][..])
        .split('\t')
        .collect();
    if parts.len() < 12 {
        return None;
    }

    let epoch: f64 = parts[0].parse().ok()?;
    let len: usize = parts[1].parse().ok().unwrap_or(0);

    let ip_src = if !parts[2].is_empty() {
        parts[2]
    } else {
        parts[4]
    };
    let ip_dst = if !parts[3].is_empty() {
        parts[3]
    } else {
        parts[5]
    };

    let src: Option<IpAddr> = ip_src.parse().ok();
    let dst: Option<IpAddr> = ip_dst.parse().ok();

    let tcp_sp: Option<u16> = parts[6].parse().ok();
    let tcp_dp: Option<u16> = parts[7].parse().ok();
    let udp_sp: Option<u16> = parts[8].parse().ok();
    let udp_dp: Option<u16> = parts[9].parse().ok();

    let (proto, src_port, dst_port) = if tcp_sp.is_some() || tcp_dp.is_some() {
        (Some(L4Proto::Tcp), tcp_sp, tcp_dp)
    } else if udp_sp.is_some() || udp_dp.is_some() {
        (Some(L4Proto::Udp), udp_sp, udp_dp)
    } else {
        (None, None, None)
    };

    let tcp_flags: Option<u16> = if parts[11].is_empty() {
        None
    } else {
        let raw = parts[11].trim();
        let raw = raw.strip_prefix("0x").unwrap_or(raw);
        u16::from_str_radix(raw, 16).ok()
    };

    let ts = epoch_to_ts(epoch);

    let mut row = PacketRow {
        index: 0, // assigned by UI when appended
        ts,
        len,
        src,
        dst,
        proto,
        src_port,
        dst_port,
        summary: String::new(),
        flow: None,
        flow_dir: None,
        tcp_seq: None,
        tcp_ack: None,
        tcp_flags,
        payload: Vec::new(),
    };

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
        row.flow_dir = Some(if flipped {
            FlowDir::BtoA
        } else {
            FlowDir::AtoB
        });
        row.flow = Some(fk);
    }

    row.summary = crate::pcap::summarize(&row);

    // If tshark protocol column is available and more specific, use it in summary prefix.
    // (We keep this best-effort, and don’t change proto semantics.)
    let proto_col = parts[10].trim();
    if !proto_col.is_empty() {
        row.summary = format!("{proto_col} {}", row.summary);
    }

    Some(row)
}

fn spawn_tshark_child_fields(
    iface: &str,
    bpf: Option<&str>,
    dfilter: Option<&str>,
) -> Result<Child> {
    // -l: line buffered; -n: no name resolution
    let mut cmd = Command::new("tshark");

    let mut args: Vec<String> = vec!["-l".into(), "-n".into(), "-i".into(), iface.into()];

    if let Some(expr) = bpf {
        args.push("-f".into());
        args.push(expr.into());
    }

    if let Some(expr) = dfilter {
        args.push("-Y".into());
        args.push(expr.into());
    }

    args.extend(
        [
            "-T",
            "fields",
            "-E",
            "separator=	",
            "-E",
            "occurrence=f",
            "-E",
            "header=n",
            "-e",
            "frame.time_epoch",
            "-e",
            "frame.len",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "ipv6.src",
            "-e",
            "ipv6.dst",
            "-e",
            "tcp.srcport",
            "-e",
            "tcp.dstport",
            "-e",
            "udp.srcport",
            "-e",
            "udp.dstport",
            "-e",
            "_ws.col.Protocol",
            "-e",
            "tcp.flags",
        ]
        .iter()
        .map(|s| s.to_string()),
    );

    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

    cmd.spawn().context("failed to spawn tshark")
}

/// Spawn a background `tshark` process and stream parsed packets into a channel.
pub fn spawn_live_capture_tshark_fields(
    iface: String,
    bpf: Option<String>,
) -> Result<Receiver<PacketRow>> {
    let _ver = tshark_version().context("tshark not available (required for --live)")?;

    let (tx, rx) = mpsc::channel::<PacketRow>();

    thread::spawn(move || {
        let mut child = match spawn_tshark_child_fields(&iface, bpf.as_deref(), dfilter.as_deref())
        {
            Ok(c) => c,
            Err(_) => return,
        };

        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            return;
        };

        let reader = BufReader::new(stdout);
        for line in reader.lines().flatten() {
            if let Some(row) = parse_tshark_fields_line(&line) {
                if tx.send(row).is_err() {
                    break;
                }
            }
        }

        let _ = child.kill();
        let _ = child.wait();
    });

    Ok(rx)
}

#[cfg(test)]
mod tests {

    #[test]
    fn friendly_error_detects_permission_denied() {
        let msg = friendly_live_capture_error("Permission denied").unwrap();
        assert!(msg.to_lowercase().contains("permissions"));
    }

    #[test]
    fn friendly_error_detects_unknown_device() {
        let msg = friendly_live_capture_error("No such device").unwrap();
        assert!(msg.to_lowercase().contains("--list-ifaces"));
    }

    use super::*;

    #[test]
    fn parse_version_first_line() {
        let s = "TShark (Wireshark) 4.2.4
Copyright ...
";
        assert_eq!(
            parse_tshark_version_output(s),
            Some("TShark (Wireshark) 4.2.4".to_string())
        );
    }

    #[test]
    fn parse_ifaces_basic() {
        let s = "1. en0
2. lo0 (Loopback)
3. awdl0 (Apple Wireless Direct Link interface)
";
        let ifaces = parse_tshark_ifaces_output(s);
        assert_eq!(ifaces.len(), 3);
        assert_eq!(ifaces[0].index, 1);
        assert_eq!(ifaces[0].name, "en0");
        assert_eq!(ifaces[0].desc, None);
        assert_eq!(ifaces[1].name, "lo0");
        assert_eq!(ifaces[1].desc.as_deref(), Some("Loopback"));
    }

    #[test]
    fn parse_tshark_fields_line_tcp() {
        // epoch, len, ip.src, ip.dst, ipv6.src, ipv6.dst, tcp sp/dp, udp sp/dp, proto col, flags
        let line = "1700000000.123	60	1.2.3.4	5.6.7.8			12345	443			TCP	0x0012";
        let row = parse_tshark_fields_line(line).unwrap();
        assert_eq!(row.len, 60);
        assert_eq!(row.proto, Some(L4Proto::Tcp));
        assert_eq!(row.src_port, Some(12345));
        assert_eq!(row.dst_port, Some(443));
        assert_eq!(row.tcp_flags, Some(0x12));
        assert!(row.summary.contains("TCP"));
    }

    #[test]
    fn parse_tshark_fields_line_udp_ipv6() {
        let line = "1700000000.000	42			2001:db8::1	2001:db8::2					53	5353	UDP	";
        let row = parse_tshark_fields_line(line).unwrap();
        assert_eq!(row.proto, Some(L4Proto::Udp));
        assert_eq!(row.src_port, Some(53));
        assert_eq!(row.dst_port, Some(5353));
    }
}
