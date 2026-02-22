use anyhow::{anyhow, Context, Result};
use std::process::{Command, Stdio};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_first_line() {
        let s = "TShark (Wireshark) 4.2.4\nCopyright ...\n";
        assert_eq!(
            parse_tshark_version_output(s),
            Some("TShark (Wireshark) 4.2.4".to_string())
        );
    }

    #[test]
    fn parse_ifaces_basic() {
        let s = "1. en0\n2. lo0 (Loopback)\n3. awdl0 (Apple Wireless Direct Link interface)\n";
        let ifaces = parse_tshark_ifaces_output(s);
        assert_eq!(ifaces.len(), 3);
        assert_eq!(ifaces[0].index, 1);
        assert_eq!(ifaces[0].name, "en0");
        assert_eq!(ifaces[0].desc, None);
        assert_eq!(ifaces[1].name, "lo0");
        assert_eq!(ifaces[1].desc.as_deref(), Some("Loopback"));
    }
}
