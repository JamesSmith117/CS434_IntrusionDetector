### Must be done

 Project setup: Python env + pinned deps (at minimum Scapy; add others only when you actually use them).

 Offline capture path: read and iterate packets from a pcap file reliably (your main reproducible demo path).

 Core fields extracted: src/dst IP, src/dst port (where applicable), protocol, timestamp per packet or per summarized record.

 Time-bucketed view: counts/stats in fixed time windows (pick 1–2 window sizes and stick to them for now).

 Proof it works: run on a sample pcap and save/print a small summary (e.g. top talkers, basic per-window counts) so you can verify the pipeline end-to-end.


### Should get done

 Clean module boundaries: separate capture/read, parse/features, and aggregation so Weeks 3–4 detection plugs in cleanly.

 Live capture (optional path): separate CLI/flag for live sniff if your machine permissions/interface setup allow it—don’t block the project on this.

 Lightweight persistence of summaries: write rolling window stats to a simple file (CSV/JSON lines) for debugging and later dashboard reuse.


### Maybe do

 Flow-ish tracking: basic per (src IP, dst IP, dst port) counters to prep for brute-force / scan heuristics later.

 Synthetic tiny pcaps: minimal captures or scripts that generate predictable patterns (helps next week’s detection tests).

 Perf guardrails: simple timing/logging on pcap processing speed if files are large (only matters if you already see slowness).
If you want this tightened further, say whether your instructor expects live capture this week or if pcap-only is acceptable for the milestone.