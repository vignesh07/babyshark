# babyshark — Beginner Navigation + Summaries (TODO)

Goal: make babyshark useful for people who aren’t fluent in networking.

Design principle: **progressive disclosure**.
- Default: human-friendly summaries + buckets + “weird stuff”.
- Always available: raw flows/packets/stream views.

Non-goals (for v0.1): full Wireshark protocol tree; exhaustive dissectors.

---

## P0 — Must-have for “PCAPs for humans” release

### Overview screen ("What’s going on?")
- [x] New top-level view: **Overview** (keybinding: `o`)
- [ ] Traffic mix widgets:
  - [ ] packets/sec sparkline (simple)
  - [x] TCP vs UDP %
  - [x] Top ports histogram (53/80/443/5353/etc.)
- [ ] “Top talkers” table:
  - [x] Hosts by bytes
  - [ ] Hosts by packets
- [ ] “Top flows” table:
  - [x] Top N flows by bytes
  - [ ] Top N flows by packets
- [ ] Live mode: show capture duration + approx pps + dropped packets if available

### Buckets that map to human intent
- [x] Add a bucket bar / filter menu:
  - [x] Web (80/443 + HTTP/TLS)
  - [x] DNS (53)
  - [x] Local discovery/noise (mDNS 5353, SSDP 1900)
  - [x] QUIC/HTTP3 (443/udp)
  - [x] Other
- [x] Clicking a bucket applies a filter to the flow list
- [x] Buckets show counts (flows, packets, bytes)

### “Weird stuff” mode (guided troubleshooting)
- [ ] New view: **Weird** (keybinding: `W`)
- [ ] Detectors (each shows count + “why it matters” + click to filter):
  - [ ] TCP resets (RST)
  - [ ] SYN retries / no handshake completion (heuristic)
  - [ ] Out-of-order / retransmit hints (if available from tshark fields)
  - [ ] DNS failures (NXDOMAIN/SERVFAIL) (pcap: parse DNS; live: tshark fields)
  - [ ] High-latency flows (gap between packets / request→response heuristic)
- [ ] “Next click” suggestions per detector

### Domain-first view (things humans recognize)
- [ ] New view: **Domains** (keybinding: `D`)
- [ ] Extract domains:
  - [ ] DNS queries
  - [ ] TLS SNI (from tshark live; from pcap if parseable)
  - [ ] HTTP Host header (plaintext)
- [ ] Tables:
  - [ ] Top domains by connections
  - [ ] Top domains by bytes
  - [ ] Domains with most failures (DNS failures / handshake issues)
- [ ] Click domain → filters flows to that domain

### Explain/Glossary (micro-tutor)
- [ ] “Explain selected flow” panel or popup (keybinding: `?`)
  - [ ] Plain-English summary: what this likely is, who’s client/server
  - [ ] Highlight key signals (RST, handshake, DNS response code, etc.)
- [ ] Inline glossary for:
  - [ ] SYN/ACK/FIN/RST
  - [ ] DNS NXDOMAIN/SERVFAIL
  - [ ] TCP vs UDP vs QUIC

---

## P1 — Strong follow-ups (still in first release if time)

### Story mode (guided workflows)
- [ ] Command palette entries:
  - [ ] “Why is my internet slow?”
  - [ ] “Why can’t I reach a site?”
  - [ ] “VPN flaky?”
- [ ] Each story is a sequence of filters + explanations

### Better live capture ergonomics
- [ ] `--bpf "..."` capture filter pass-through (tshark `-f`)
- [ ] UI: show active filters (bpf + dfilter)
- [ ] UI: show tshark status (running/exited) + last stderr line

### Shareable “case file” improvements
- [ ] Bookmarks for packets (not just flows)
- [ ] Markdown report includes:
  - [ ] “Weird stuff” summary
  - [ ] Domains summary
  - [ ] Selected flow packet excerpt

---

## P2 — Nice-to-haves

### Visual tools (TUI-friendly)
- [ ] Host graph/constellation view
- [ ] Timeline heat-strip with click-to-zoom window
- [ ] Port histogram view

### Performance + correctness
- [ ] Better TCP reassembly (gaps/retransmit markers; don’t just append gaps)
- [ ] QUIC heuristics

### Distribution
- [ ] GitHub Releases with prebuilt binaries
- [ ] Homebrew tap

---

## Notes

- We can keep raw mode views intact: Flows/Packets/Stream stay power-user friendly.
- The novelty is “PCAPs for humans”: overviews, buckets, weird-stuff, domains, explainers.
