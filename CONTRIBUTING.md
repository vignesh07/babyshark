# Contributing to babyshark

Thanks for checking out babyshark.

## TL;DR
Right now the **best way to contribute is by filing issues**.

- I’m prioritizing **real-world bug reports** and **high-signal UX feedback** from users.
- PRs are welcome, but I may not be able to review them quickly yet.

If you want to help, a great issue beats a half-baked PR.

---

## What I’m looking at

### ✅ High priority
- Bugs that affect basic usability (navigation, crashes, broken drilldowns)
- Live-capture problems (tshark availability, permissions, interface selection)
- Incorrect/misleading UI (wrong labels, confusing hints)
- Clear feature requests that improve beginner workflows (Overview/Domains/Weird/Explain)

### ⚠️ Lower priority (for now)
- Large refactors
- New architecture or big dependency changes
- Broad “add protocol X” requests without a user story

---

## How to file a great issue

### 1) Pick a clear title
Good:
- "Esc doesn’t work in Flows on macOS Terminal"
- "Domains Enter sometimes does nothing"
- "Packets view needs paging/scroll"

Less helpful:
- "Broken"
- "Doesn’t work"

### 2) Include the essentials
Please include:
- **OS + version** (macOS/Linux/Windows)
- **Terminal** (Terminal.app/iTerm2/VS Code/etc.)
- How you installed:
  - GitHub Release binary / `cargo install` / build from source
- What you ran:
  - `babyshark --pcap …` or `babyshark --live …`
- What you expected vs what happened

### 3) Repro steps
Numbered steps are ideal:
1. Run `babyshark --live en0`
2. Press `D`
3. Select a domain
4. Press Enter
5. (Observed result)

### 4) If it’s a live-capture issue
Please add:
- Output of `tshark -v`
- Output of `babyshark --list-ifaces`
- Any error shown in the Overview “last:” line

### 5) Screenshots / PCAPs
- Screenshots are very helpful.
- **Please redact** private IPs/domains if posting publicly.
- If you can share a small PCAP that reproduces the issue, even better.

---

## Feature requests: what helps most

If you’re requesting a feature, answer:
- Who is the user? (beginner / network engineer / teacher)
- What problem are they trying to solve?
- What should the UI show/do?

Example:
> As a beginner, I want a "why is this slow" checklist that always suggests the next click.

---

## Code contributions

If you want to send a PR anyway:
- Keep it small and focused
- Add a test when it’s easy (especially for parsing or UI state)
- Run locally:
  - `cargo test --manifest-path rust/Cargo.toml`

Thanks again — issues are the fastest way to make babyshark better right now.
