# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Per-flow analysis in Flows/Details:
  - health badge (green/yellow/red)
  - directional asymmetry label
  - TCP timing metrics (handshake RTT, server think, transfer duration)
- Timeline view (`T`) with two sub-tabs:
  - Gantt (phase-colored flow duration bars: handshake / TLS / data / close)
  - Scatter (per-packet direction/retransmit markers)
- Timeline educational features:
  - Hostname labels instead of raw IPs (with HTTPS/HTTP/DNS port hints)
  - Color legend explaining what each phase/dot color means
  - Pattern callouts (simultaneous opens, DNS-before-TLS, retransmission warnings)
  - Plain-English "What happened" narrative in details panel
- Timeline keyboard controls and drilldown:
  - `Tab`/`Shift-Tab` switch Gantt/Scatter
  - `PgUp`/`PgDn` paging
  - `Enter` to open Packets for selected timeline flow
- Timeline navigation hints in Overview onboarding and Help modal.
- New weird detectors:
  - deprecated TLS versions (<= 1.1)
  - chatty hosts bursts (>= 10 flows to a destination within 60s)
- TLS version hint extraction on packets and TLS version display in flow details.
- `FlowStats` now stores per-flow `first_ts`/`last_ts` for timeline rendering.

### Changed
- UI refactor: extracted hexdump rendering into `ui/hexdump.rs`.
- UI refactor: extracted overview page builder into `ui/overview.rs`.
- README expanded with flow analysis and detector examples.

### Fixed
- Asymmetry labels now use beginner-friendly `DL/UL` when local side can be inferred, with safe `A>B/B>A` fallback when ambiguous (avoids canonical-direction inversion).
- Chatty-host detector now groups by first observed packet destination (not canonical key destination).
- TLS version detection now uses ServerHello version selection (including TLS 1.3 supported_versions), avoiding ClientHello legacy-version mislabeling.
- Timeline row label truncation is now UTF-8 safe (prevents panic around multibyte characters like `↔`).
- Timeline range and per-flow first/last timestamps now use min/max packet timestamps (robust to out-of-order capture rows).
- Details pane now follows the selected Timeline row (instead of stale Flows selection).
- Scatter renderer packet-count tracking no longer overflows on very dense columns.

## [0.2.1] - 2026-02-25

### Added
- Linux Arch install instructions for `tshark` in README.

### Changed
- Removed legacy Go scaffolding from the repo (Rust-only runtime path).
- Refactored UI modal/help/explain/search rendering into a dedicated `ui/modals.rs` module.
- Hardened live capture process handling and stream error reporting.

### Fixed
- Live `tshark` capture now terminates when quitting the app (`q`) and on TUI teardown.
- Rust compiler warnings in tests/fixtures and hints cleanup.

## [0.2.0] - 2026-02-23

### Added
- Interactive launcher when running `babyshark` with no args (choose Live capture vs Open PCAP).
- Lowercase navigation aliases (`d` Domains, `w` Weird, `f` Flows outside Packets).
- `Backspace` as an alias for back navigation (in addition to `Esc`).
- Number shortcuts `1`–`9` to jump-select items in Overview/Domains/Weird.
- Packets view paging/scrolling (`PgUp`/`PgDn`).
- Hostname hints in Flows and Packets (best-effort IP → hostname labels).
- Learning mode toggle (`L`) with inline guidance in the Flows details pane.
- Domains clarity: `ips=*` marker + separate “Observed IPs (from flows)” vs “DNS A/AAAA IPs (when visible)”.
- CONTRIBUTING.md (issues-first policy; PRs closed during early launch window).
- MIT license.
- README improvements: quickstart, troubleshooting, and screenshot companion explainers.

### Changed
- UI wording: replaced “click” with “select” where mouse is not supported.
- Explain/Glossary: clearer “follow stream” definition and TLS encryption expectations.
- CI: removed Go steps; CI now runs Rust tests only.

### Fixed
- Domains/Weird Enter drilldown: clamp selection so Enter always applies when items exist.


## [0.1.0] - 2026-02-23

### Added
- TUI views:
  - Overview dashboard (traffic mix, top ports/hosts/flows, drill-down entry points).
  - Flows list with filtering (`/`) and protocol toggles (`t`/`u`).
  - Packets view and Follow stream view.
  - Weird stuff view (`W`) with detectors and drill-down.
  - Domains view (`D`) with drill-down to flows.
  - Explain modal (`?`) and Glossary (`g`).
- Live capture support via `tshark` (`--list-ifaces`, `--live <iface>`), including surfacing stderr/status.
- Domain extraction (best-effort): DNS qname, HTTP Host, TLS SNI.
- Domain IP hints:
  - DNS A/AAAA when visible
  - Observed IPs from flows for DoH/DoT/cached DNS scenarios
- Basic “weird” detectors (e.g., TCP resets, handshake not completed, latency-ish, reliability hints).
- Export/reporting from Flows (`E`).

[Unreleased]: https://github.com/vignesh07/babyshark/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/vignesh07/babyshark/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/vignesh07/babyshark/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/vignesh07/babyshark/releases/tag/v0.1.0
