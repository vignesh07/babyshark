# babyshark — Launch Tasks (buildbot queue)

This is the concrete work list to get to a “PCAPs for humans” launch.

## Guiding principles
- **Dashboard-first:** Overview/Domains/Weird should give useful answers without Wireshark expertise.
- **Progressive disclosure:** Keep Flows/Packets/Stream as the escape hatch for power users.
- **Live mode parity:** Beginner features must work for `--live` (not just offline PCAP).

---

## Status: already shipped (done)
- Overview: clickable dashboard + drilldowns (ports/hosts/flows)
- Weird view (`W`) + detectors:
  - TCP resets (RST)
  - Handshake not completed (SYNs without SYN,ACK heuristic)
- Domains view (`D`) v1:
  - DNS parsing (offline)
  - Domain extraction from HTTP Host + TLS SNI (offline, best-effort)
  - Drilldown: domain → subset flows (via resolved IPs)
- Explain modal (`?`) for selected flow: plain-English summary + next steps (best-effort)
- Live mode: tshark fields populate `PacketRow` hostname hints (`dns.qry.name`, TLS SNI, HTTP Host)

---

## P0 — Must-have before launch (queue)

### A) Live-mode parity for Domains + Explain (highest priority)
1. **(shipped)** Extract hostnames in live mode via tshark fields (payload bytes aren’t available today):
   - DNS: `dns.qry.name`, `dns.flags.rcode`, and if possible `dns.a`, `dns.aaaa`
   - TLS: `tls.handshake.extensions_server_name`
   - HTTP: `http.host`
2. **(shipped)** Update live parsing to populate `PacketRow.{dns_qname,http_host,tls_sni}` from tshark columns.
3. **(shipped)** Add unit tests for parsing the new live TSV line formats.
4. Confirm: Domains view shows hostnames during `--live` capture.

### B) Overview completeness
1. Add packets/sec sparkline (simple, coarse bucketed).
2. Add “Top talkers by packets” (not just bytes).
3. Add “Top flows by packets” (not just bytes).
4. Live mode: show capture duration + approx pps + dropped packets if available.

### C) Weird-mode completeness
1. DNS failures detector (NXDOMAIN/SERVFAIL) (offline + live fields).
2. Out-of-order / retransmit hints (prefer tshark fields if available).
3. High-latency flow heuristic (requires correct timestamps).
4. “Next click” suggestions per detector (structured, consistent).

### D) Domains-mode completeness
1. Top domains by connections.
2. Top domains by bytes.
3. Domains with most failures (DNS + handshake failures if we can infer).

### E) Explain/Glossary completeness
1. Glossary popover/inline for:
   - SYN/ACK/FIN/RST
   - DNS NXDOMAIN/SERVFAIL
   - TCP vs UDP vs QUIC

---

## Correctness / platform blockers
- **PCAPNG timestamps**: ensure we parse timestamps correctly (needed for sparkline, latency, and time-based weird detectors).

---

## Buildbot execution rules
- One meaningful user-visible change per run.
- `cargo test --manifest-path rust/Cargo.toml` must pass.
- Commit + push on success.
- No spam: do not post “no change” messages.
