### Done

- Project setup: Python venv + pinned deps (`requirements.txt`, Scapy pinned).
- Offline capture path: stream packets from pcap/pcapng via `netsentry/pcap.py` (`PcapReader`).
- Core fields: `PacketSummary` — IPs, ports (TCP/UDP), protocol, timestamp, size (`records.py` / `pcap.py`).
- Time-bucketed stats: default **1s** and **60s** windows (`aggregate.py`, `report.py`).
- End-to-end proof: `scripts/gen_sample_pcap.py` + `python -m netsentry <pcap> [--json …]`.
- Synthetic tiny pcaps: `scripts/gen_sample_pcap.py` for predictable local demos.
- Clean module boundaries: capture/read, parse/features, detection, and reporting split into dedicated modules.
- Live capture path: optional CLI mode (`--live`) implemented and validated on local machine.
- Rolling window stats export: `--window-stats-out` to CSV or JSON lines for debugging and dashboard reuse (`README.md` rolling window section).
- **Detection engine** (`netsentry/detect.py`): rule-based heuristics for TCP vertical port scans, SYN-only flood buckets, DNS volume/large UDP/53 payloads, and brute-force-style traffic to sensitive ports; uses `tcp_flags` + `features.bucket_index`. Documented in `README.md` (Netsentry Directory).
- **Structured alerts:** `Alert` dataclass (`netsentry/alerts.py`); detection output merged into pipeline summary, printed in the text report, and included in `--json` (`report.py` / `__main__.py`).
- **Alert persistence:** `--alerts-out` writes JSON, JSONL, CSV, or SQLite (`.sqlite`/`.db`); includes `ingest_wall`, `source`, and alert fields for dashboard/history (`persist.py`; documented in `README.md`).
- **Demo / report ammo:** `scripts/gen_demo_pcaps.py` — one synthetic pcap per `rule_id`, `--verify` self-check; commands and expected IDs in `README.md` (Detection demo scenarios).


### Must be done

*(Next on the proposal timeline: Week 5 Flask dashboard; Week 6 controlled tests + final report — see `README.md`.)*



### Should get done

- [ ] Flow-ish tracking: reusable per-(src IP, dst IP, dst port) counters exposed from features (detection already uses similar grouping internally).

- [ ] Perf guardrails: simple timing/logging on pcap processing speed if files are large (only matters if you already see slowness).

### Maybe do

- [ ] Expand packet parsing coverage (ICMP details, IPv6 extension handling, and non-TCP/UDP protocol labeling checks).

- [ ] Add small validation tests for packet processing (field extraction + window bucket correctness on synthetic pcaps).

- [ ] Rule-specific demo pcaps are covered by `scripts/gen_demo_pcaps.py`; add more edge-case pcaps (e.g. mixed benign + attack) if the final report needs them.

- [ ] Add a quick packet-processing benchmark command (packets/sec + runtime on a medium pcap).


If you want this tightened further, say whether your instructor expects live capture this week or if pcap-only is acceptable for the milestone.
