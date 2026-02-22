# babyshark

Flows-first PCAP TUI (case files, gorgeous UX). Private alpha.

## Dev (Rust)

Run against a file:

```bash
cargo run --manifest-path rust/Cargo.toml -- --pcap ./capture.pcap
```

List live capture interfaces (requires tshark):

```bash
cargo run --manifest-path rust/Cargo.toml -- --list-ifaces
```
