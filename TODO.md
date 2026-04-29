### Done

- Project setup: Python venv + pinned deps (`requirements.txt`, Scapy pinned).
- Offline capture path: stream packets from pcap/pcapng via `netsentry/pcap.py` (`PcapReader`).
- Core fields: `PacketSummary` — IPs, ports (TCP/UDP), protocol, timestamp, size (`records.py` / `pcap.py`).
- Time-bucketed stats: default **1s** and **60s** windows (`aggregate.py`, `report.py`).
- End-to-end proof: `scripts/gen_sample_pcap.py` + `python -m netsentry <pcap> [--json …]`.
- Synthetic tiny pcaps: `scripts/gen_sample_pcap.py` for predictable local demos.


### Must be done

- [ ] Clean module boundaries: separate capture/read, parse/features, and aggregation so Weeks 3–4 detection plugs in cleanly.

- [ ] Live capture (optional path): separate CLI/flag for live sniff if your machine permissions/interface setup allow it—don’t block the project on this.

- [ ] Lightweight persistence of summaries: write rolling window stats to a simple file (CSV/JSON lines) for debugging and later dashboard reuse.



### Should get done

- [ ] Flow-ish tracking: basic per (src IP, dst IP, dst port) counters to prep for brute-force / scan heuristics later.

- [ ] Perf guardrails: simple timing/logging on pcap processing speed if files are large (only matters if you already see slowness).

### Maybe do

- [ ] Expand packet parsing coverage (ICMP details, IPv6 extension handling, and non-TCP/UDP protocol labeling checks).

- [ ] Add small validation tests for packet processing (field extraction + window bucket correctness on synthetic pcaps).

- [ ] Create 2-3 additional sample pcaps with predictable traffic patterns (normal mix, burst traffic, simple scan-like behavior).

- [ ] Add a quick packet-processing benchmark command (packets/sec + runtime on a medium pcap).

- [ ] Write a short “Week 2 packet processing complete” checklist in `README.md` with run commands and expected output.


If you want this tightened further, say whether your instructor expects live capture this week or if pcap-only is acceptable for the milestone.
