# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/vignesh07/babyshark/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vignesh07/babyshark/releases/tag/v0.1.0
