# babyshark

Flows-first PCAP TUI with live capture (via `tshark`).

**Status:** alpha. Offline PCAP viewing works without Wireshark. Live capture requires `tshark`.

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

### Option A: build from source (recommended for now)

Prereqs:
- Rust toolchain (stable)
- (Live mode only) `tshark`

```bash
git clone https://github.com/vignesh07/babyshark
cd babyshark/rust
cargo build --release
./target/release/babyshark --help
```

### Option B: cargo install (dev-friendly)

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

## Keybindings (TUI)

- `q` quit
- Flows view:
  - `↑/↓` or `j/k` move
  - `Enter` packets
  - `/` filter
  - `t` / `u` toggle TCP / UDP
  - `b` bookmark flow
  - `E` export report
- Packets view:
  - `f` follow stream
  - `Esc` back
- Stream view:
  - `/` search
  - `n` / `N` next / prev match
  - `Tab` / `Shift-Tab` cycle stream direction
  - `↑/↓` scroll
  - `Esc` back/clear

---

## Output files

When you bookmark/export, babyshark writes next to the PCAP in a hidden directory:

- `.babyshark/case.json` — bookmarks
- `.babyshark/report.md` — latest report (overwritten)
- `.babyshark/report-YYYYMMDD-HHMMSS.md` — versioned reports

---

## Roadmap

- `--bpf` capture filter pass-through for live mode
- Better protocol hints (DNS/TLS heuristics)
- Improved TCP reassembly (gap/retransmit markers)
- Prebuilt binaries via GitHub Releases

---

## License

TBD (choose MIT/Apache-2.0/etc.)
