use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
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
/// Field order (see `build_tshark_live_args`):
/// frame.time_epoch, frame.len,
/// ip.src, ip.dst, ipv6.src, ipv6.dst,
/// tcp.srcport, tcp.dstport, udp.srcport, udp.dstport,
/// _ws.col.Protocol,
/// tcp.flags,
/// tcp.analysis.retransmission, tcp.analysis.out_of_order,
/// dns.qry.name, dns.flags.rcode, dns.a, dns.aaaa,
/// tls.handshake.extensions_server_name, http.host
pub fn parse_tshark_fields_line(line: &str) -> Option<PacketRow> {
    let parts: Vec<&str> = line
        .trim_end_matches(&['\n', '\r'][..])
        .split('\t')
        .collect();
    // Keep backward-compatible with older line formats, but we expect at least the base columns.
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

    // Extended live fields (indices based on `build_tshark_live_args`).
    let tcp_retransmission = parts.get(12).is_some_and(|s| !s.trim().is_empty());
    let tcp_out_of_order = parts.get(13).is_some_and(|s| !s.trim().is_empty());

    let dns_qname = parts.get(14).map(|s| s.trim()).filter(|s| !s.is_empty());
    let tls_sni = parts.get(18).map(|s| s.trim()).filter(|s| !s.is_empty());
    let http_host = parts.get(19).map(|s| s.trim()).filter(|s| !s.is_empty());

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
        tcp_retransmission,
        tcp_out_of_order,
        dns_qname: dns_qname.map(|s| s.to_string()),
        dns_rcode: parts.get(15).and_then(|s| {
            let s = s.trim();
            if s.is_empty() {
                None
            } else {
                s.parse::<u16>().ok()
            }
        }),
        http_host: http_host.map(|s| s.to_string()),
        tls_sni: tls_sni.map(|s| s.to_string()),
        tls_version: None,
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

    crate::hints::populate_hints(&mut row);

    row.summary = crate::pcap::summarize(&row);

    // If tshark protocol column is available and more specific, use it in summary prefix.
    // (We keep this best-effort, and don’t change proto semantics.)
    let proto_col = parts[10].trim();
    if !proto_col.is_empty() {
        row.summary = format!("{proto_col} {}", row.summary);
    }

    Some(row)
}

fn build_tshark_live_args(
    iface: &str,
    bpf: Option<&str>,
    dfilter: Option<&str>,
    write_pcap: Option<&str>,
) -> Vec<String> {
    let mut args: Vec<String> = vec!["-l".into(), "-n".into(), "-i".into(), iface.into()];

    if let Some(expr) = bpf {
        args.push("-f".into());
        args.push(expr.into());
    }

    if let Some(expr) = dfilter {
        args.push("-Y".into());
        args.push(expr.into());
    }

    if let Some(path) = write_pcap {
        args.push("-w".into());
        args.push(path.into());
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
            // TCP analysis hints (best-effort; requires Wireshark dissector).
            "-e",
            "tcp.analysis.retransmission",
            "-e",
            "tcp.analysis.out_of_order",
            // Live-mode hostname extraction (for Domains/Explain parity).
            "-e",
            "dns.qry.name",
            "-e",
            "dns.flags.rcode",
            "-e",
            "dns.a",
            "-e",
            "dns.aaaa",
            "-e",
            "tls.handshake.extensions_server_name",
            "-e",
            "http.host",
        ]
        .iter()
        .map(|s| s.to_string()),
    );

    args
}

fn spawn_tshark_child_fields(
    iface: &str,
    bpf: Option<&str>,
    dfilter: Option<&str>,
    write_pcap: Option<&str>,
) -> Result<Child> {
    // -l: line buffered; -n: no name resolution
    let mut cmd = Command::new("tshark");
    let args = build_tshark_live_args(iface, bpf, dfilter, write_pcap);

    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

    cmd.spawn().context("failed to spawn tshark")
}

fn format_tshark_exit_status(status: ExitStatus) -> String {
    if status.success() {
        return "[tshark exited: success]".to_string();
    }
    if let Some(code) = status.code() {
        return format!("[tshark exited: code {code}]");
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return format!("[tshark exited: signal {sig}]");
        }
    }
    "[tshark exited: unknown status]".to_string()
}

fn drain_tshark_stderr(
    stderr: std::process::ChildStderr,
    tx_err: mpsc::Sender<String>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line_res in reader.lines() {
            match line_res {
                Ok(line) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    // Only keep recent errors; UI stores last line.
                    if tx_err.send(line.to_string()).is_err() {
                        break;
                    }
                }
                Err(err) => {
                    let _ = tx_err.send(format!("[tshark stderr read error] {err}"));
                    break;
                }
            }
        }
    })
}

fn forward_tshark_stdout(
    stdout: std::process::ChildStdout,
    tx: &mpsc::Sender<PacketRow>,
    tx_err: &mpsc::Sender<String>,
) -> bool {
    let reader = BufReader::new(stdout);
    for line_res in reader.lines() {
        let line = match line_res {
            Ok(line) => line,
            Err(err) => {
                let _ = tx_err.send(format!("[tshark stdout read error] {err}"));
                return false;
            }
        };
        if let Some(row) = parse_tshark_fields_line(&line) {
            if tx.send(row).is_err() {
                // UI receiver dropped; caller should stop tshark.
                return true;
            }
        }
    }
    false
}

/// Spawn a background `tshark` process and stream parsed packets into a channel.
pub fn spawn_live_capture_tshark_fields(
    iface: String,
    bpf: Option<String>,
    dfilter: Option<String>,
) -> Result<(Receiver<PacketRow>, Receiver<String>, Sender<()>)> {
    let _ver = tshark_version().context("tshark not available (required for --live)")?;

    let (tx, rx) = mpsc::channel::<PacketRow>();
    let (tx_err, rx_err) = mpsc::channel::<String>();
    let (tx_stop, rx_stop) = mpsc::channel::<()>();

    thread::spawn(move || {
        let mut child =
            match spawn_tshark_child_fields(&iface, bpf.as_deref(), dfilter.as_deref(), None) {
                Ok(c) => c,
                Err(err) => {
                    let _ = tx_err.send(format!("[tshark spawn failed] {err}"));
                    return;
                }
            };

        let Some(stdout) = child.stdout.take() else {
            let _ = tx_err.send("[tshark error] stdout pipe unavailable".to_string());
            let _ = child.kill();
            let _ = child.wait();
            return;
        };
        let stderr = child.stderr.take();
        let child = Arc::new(Mutex::new(child));

        // Listen for explicit app shutdown and terminate tshark promptly.
        let child_stop = Arc::clone(&child);
        let tx_err_stop = tx_err.clone();
        let stop_handle = thread::spawn(move || {
            if rx_stop.recv().is_err() {
                return;
            }

            let mut guard = match child_stop.lock() {
                Ok(g) => g,
                Err(_) => {
                    let _ = tx_err_stop.send("[tshark stop error] child lock poisoned".to_string());
                    return;
                }
            };
            if let Err(err) = guard.kill() {
                if err.kind() != std::io::ErrorKind::InvalidInput {
                    let _ = tx_err_stop.send(format!("[tshark stop error] {err}"));
                }
            }
        });

        // Drain stderr so tshark can't block on a full stderr pipe.
        let stderr_handle = stderr.map(|stderr| drain_tshark_stderr(stderr, tx_err.clone()));

        let ui_gone = forward_tshark_stdout(stdout, &tx, &tx_err);
        if ui_gone {
            let mut guard = match child.lock() {
                Ok(g) => g,
                Err(_) => {
                    let _ = tx_err.send("[tshark error] child lock poisoned".to_string());
                    return;
                }
            };
            let _ = guard.kill();
        }

        let wait_result = {
            let mut guard = match child.lock() {
                Ok(g) => g,
                Err(_) => {
                    let _ = tx_err.send("[tshark wait error] child lock poisoned".to_string());
                    return;
                }
            };
            guard.wait()
        };
        match wait_result {
            Ok(status) => {
                let _ = tx_err.send(format_tshark_exit_status(status));
            }
            Err(err) => {
                let _ = tx_err.send(format!("[tshark wait error] {err}"));
            }
        }

        if let Some(handle) = stderr_handle {
            let _ = handle.join();
        }
        drop(stop_handle);
    });

    Ok((rx, rx_err, tx_stop))
}

#[cfg(test)]
mod tests {
    use crate::pcap::L4Proto;

    use super::{
        build_tshark_live_args, friendly_live_capture_error, parse_tshark_fields_line,
        parse_tshark_ifaces_output, parse_tshark_version_output,
    };

    #[test]
    fn build_tshark_live_args_includes_write_pcap() {
        let args = build_tshark_live_args("en0", None, None, Some("out.pcapng"));
        let pos = args.iter().position(|a| a == "-w").unwrap();
        assert_eq!(args[pos + 1], "out.pcapng");
    }

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
        // epoch, len, ip.src, ip.dst, ipv6.src, ipv6.dst, tcp sp/dp, udp sp/dp, proto col, flags, retrans, ooo, dns, rcode, a, aaaa, sni, host
        let line = "1700000000.123	60	1.2.3.4	5.6.7.8			12345	443			TCP	0x0012								";
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
        // columns: epoch, len, ip.src, ip.dst, ipv6.src, ipv6.dst, tcp sp/dp, udp sp/dp, proto col, flags, retrans, ooo, dns, rcode, a, aaaa, sni, host
        let line = "1700000000.000	42			2001:db8::1	2001:db8::2			53	5353	UDP								";
        let row = parse_tshark_fields_line(line).unwrap();
        assert_eq!(row.proto, Some(L4Proto::Udp));
        assert_eq!(row.src_port, Some(53));
        assert_eq!(row.dst_port, Some(5353));
    }

    #[test]
    fn parse_tshark_fields_line_hostname_hints() {
        // Ensure we populate PacketRow.{dns_qname,dns_rcode,tls_sni,http_host} from tshark fields (live mode).
        let line = "1700000001.000	74	10.0.0.2	1.1.1.1			55555	443			TLS	0x0018			example.com	0			www.example.org	example.com";
        let row = parse_tshark_fields_line(line).unwrap();
        assert_eq!(row.dns_qname.as_deref(), Some("example.com"));
        assert_eq!(row.dns_rcode, Some(0));
        assert_eq!(row.tls_sni.as_deref(), Some("www.example.org"));
        assert_eq!(row.http_host.as_deref(), Some("example.com"));
        assert!(!row.tcp_retransmission);
        assert!(!row.tcp_out_of_order);
    }
}
