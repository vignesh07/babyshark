# babyshark

**Wireshark made easy (in your terminal).**

Babyshark is a PCAP TUI that helps you answer:
- What’s using the network?
- What looks broken/weird?
- What should I click next?

**Status:** v0.1.0 (alpha).
- Offline `.pcap` / `.pcapng` viewing works without Wireshark
- Live capture requires `tshark` (Wireshark CLI)

---

## Quickstart

### Download a release (recommended)

Grab a binary from GitHub Releases:
- https://github.com/vignesh07/babyshark/releases

### Or build from source

```bash
git clone https://github.com/vignesh07/babyshark
cd babyshark/rust
cargo install --path . --force
babyshark --help
```

---

## Features

- Offline: open `.pcap` / `.pcapng` and browse:
  - flows list → packets list → follow stream
  - stream search with highlighting + `n` / `N` navigation
- Live: capture and inspect traffic in the TUI:
  - list capture interfaces
  - live capture with optional display filter
  - optional write-to-file while capturing
- Notes/export:
  - bookmark flows
  - export markdown report (latest + timestamped copies)

---

## Install

### Option A: GitHub Release (recommended)

Download a prebuilt binary:
- https://github.com/vignesh07/babyshark/releases

### Option B: build from source

Prereqs:
- Rust toolchain (stable)
- (Live mode only) `tshark`

```bash
git clone https://github.com/vignesh07/babyshark
cd babyshark/rust
cargo install --path . --force
babyshark --help
```

### Option C: cargo install (dev-friendly)

```bash
cargo install --git https://github.com/vignesh07/babyshark --bin babyshark
```

---

## Install `tshark` (required for `--live`)

`tshark` is the official Wireshark CLI.

### macOS

```bash
brew install wireshark
```

### Linux

Debian/Ubuntu:
```bash
sudo apt-get update
sudo apt-get install -y tshark
```

Fedora:
```bash
sudo dnf install -y wireshark-cli
```

Verify:
```bash
tshark --version
tshark -D
```

**Permissions note:** live capture may require elevated permissions (sudo, dumpcap caps, or being in the `wireshark` group). If babyshark prints a permission error, follow the guidance it outputs.

---

## Usage

### Offline PCAP

```bash
babyshark --pcap ./capture.pcap
```

### List live interfaces

```bash
babyshark --list-ifaces
```

### Live capture

```bash
babyshark --live en0
```

### Live capture with Wireshark display filter

```bash
babyshark --live en0 --dfilter "tcp.port==443"
```

### Live capture and write to file

```bash
babyshark --live en0 --write-pcap /tmp/live.pcapng
```

---

## Example screens (sanitized)

These are **text-only** examples of what you’ll see in the TUI. IPs/domains are anonymized.

### Overview (live)

```text
PCAP Viewer
babyshark   Overview  flows:114 packets:4227  tcp:on udp:on q=—

Overview  (D domains, W weird, F flows)
In plain English
Packets: 4227   Flows: 114   Top talker: 10.0.0.6 (2711.9KB)   Top talker (pkts): 10.0.0.6 (4046 pkts)
Live: 88s   pps~14.6   dropped~0   | last: Capturing on 'Wi‑Fi: en0'

pps: ▁▁▂▂▃▄▅▆▆▇▆▅▄▃▂▂▁  (max 1372/bucket)

Top flow (bytes): UDP 10.0.0.6:57315 ↔ 203.0.113.123:443 (1359.3KB)
Top flow (pkts):  UDP 10.0.0.6:57315 ↔ 203.0.113.123:443 (1284 pkts)

What should I click?
• Domains (human view)  (press D)
• Weird stuff (troubleshoot)  (press W)
• Flows (raw)  (press F)
  ↳ Detected: High-latency flows (rough) (29 flows)
```

### Domains

```text
Domains  (Enter show flows, s sort (conn/bytes/fail), c clear, Esc back)

  1 wikipedia.com                      conn=9  bytes=21.0KB  q=9  r=6  fail=0  ips=2
❯ 2 chat.openai.com                    conn=5  bytes=28.2KB  q=5  r=3  fail=0  ips=2

Domain details
chat.openai.com

queries=5 responses=3 failures=0

Observed IPs (from flows):
10.0.0.6
198.51.100.42

Tip: Enter applies a subset filter (prefers observed IPs; DNS IPs if available).
```

### Weird stuff

```text
Weird stuff  (Enter show flows, c clear, Esc back)

❯ 1 High-latency flows (rough)                          flows=42
  2 TCP reliability hints (retransmits / out-of-order)  flows=16
  3 TCP resets (RST)                                    flows=11
  4 Handshake not completed                             flows=0
  5 DNS failures (NXDOMAIN/SERVFAIL)                    flows=0

Why it matters
High-latency flows (rough)

If a flow takes a long time and has lots of packets, it can indicate latency,
congestion, or retries. This is a rough heuristic and depends on correct timestamps.
```

### Flows

```text
Flows [LIVE en0] (63.8 pps)  (Enter packets, / filter, t/u toggles, b bookmark, E export, o overview)  subset=domain:chat.openai.com

  1 UDP  510   10.0.0.6:59175 ↔ 203.0.113.123:443
❯ 2 TCP   32   10.0.0.6:57608 ↔ 198.51.100.42:443

Details
TCP 10.0.0.6:57608 ↔ 198.51.100.42:443

A→B: 14 pkts / 1386 bytes
B→A: 26 pkts / 26307 bytes

bookmarks: 1
```

---

## Keybindings (TUI)

Top-level:
- `o` overview
- `D` domains
- `W` weird stuff
- `F` flows
- `h` help
- `g` glossary
- `q` quit

In views:
- `Enter` drill down (domains/weird → flows, flows → packets)
- `Esc` back
- `c` clear active subset filter
- `?` explain selected flow
- `x` dismiss onboarding hint (Overview)

Flows view:
- `↑/↓` or `j/k` move
- `/` filter
- `t` / `u` toggle TCP / UDP
- `b` bookmark flow
- `E` export report

Packets view:
- `f` follow stream

Stream view:
- `/` search
- `n` / `N` next / prev match
- `Tab` / `Shift-Tab` cycle stream direction
- `↑/↓` scroll

---

## Output files

When you bookmark/export, babyshark writes next to the PCAP in a hidden directory:

- `.babyshark/case.json` — bookmarks
- `.babyshark/report.md` — latest report (overwritten)
- `.babyshark/report-YYYYMMDD-HHMMSS.md` — versioned reports

---

## Roadmap

- Prettier onboarding + docs (screenshots/gifs)
- `--bpf` capture filter pass-through for live mode
- Even better protocol hints + flow classification
- Improved TCP reassembly (gap/retransmit markers)
- Homebrew/Scoop packaging

---

## License

TBD (choose MIT/Apache-2.0/etc.)
