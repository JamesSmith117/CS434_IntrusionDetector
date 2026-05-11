CS434_IntrusionDectector

Make sure when you push that you do: 
git push -u origin main

Project Proposal: NetSentry – Lightweight Network Intrusion Detection System
Introduction / Problem

Modern networks generate large volumes of traffic, making it difficult to manually identify malicious activity. Many existing intrusion detection systems are complex and resource-heavy, limiting their usability in smaller or educational environments. This project aims to develop a lightweight and interpretable system for detecting common network attacks.

Objective

The goal of this project is to design and implement NetSentry, a network intrusion detection system that monitors traffic and identifies suspicious behavior such as port scans, flooding attacks, DNS anomalies, and brute-force attempts. The system will generate real-time alerts and provide a simple dashboard for analysis.

Approach

The system will use a modular pipeline consisting of:

Traffic Collection: Capture packets using Python (Scapy), supporting both live traffic and offline pcap files
Feature Extraction: Extract key fields such as IPs, ports, protocols, and timestamps, and track activity over time windows
Detection Engine: Apply rule-based logic to detect suspicious patterns, including:
Port scans
SYN flooding
DNS anomalies
Brute-force behavior
Alerting: Generate structured alerts with timestamps, severity, and descriptions, stored in SQLite or JSON
Dashboard: A Flask-based interface to display alerts, summaries, and simple visualizations
Expected Outcomes

The final system will detect multiple types of suspicious activity, provide clear explanations for alerts, and support both real-time and offline analysis. Effectiveness will be demonstrated through controlled test scenarios such as simulated scans and traffic bursts.

Tools and Timeline
Tools: Python, Scapy, Flask, SQLite/JSON

Timeline:

Weeks 1–2: Setup and packet processing
Weeks 3–4: Detection logic and alerts
Week 5: Dashboard development
Week 6: Testing and final report
Significance

This project demonstrates key network security concepts such as traffic analysis and intrusion detection, while emphasizing simplicity, interpretability, and practical implementation.

#############################################################################

Netsentry Directory (Current Implementation)

The `netsentry/` package contains the core offline packet-processing pipeline:

- `netsentry/__init__.py`
  - Marks `netsentry` as a Python package and stores package metadata/version.

- `netsentry/__main__.py`
  - Command-line entry point for running the pipeline with:
    - Offline mode: `python -m netsentry <pcap>`
    - Live mode: `python -m netsentry --live --count 100 --timeout 15 [--iface ...] [--filter ...]`
  - Parses CLI arguments (offline/live source, window sizes, optional JSON output, `--window-stats-out`, `--alerts-out`), runs processing, and prints results.

- `netsentry/records.py`
  - Defines the `PacketSummary` data model used across the project.
  - Stores normalized per-packet fields such as timestamp, src/dst IP, ports, protocol, and packet size.

- `netsentry/pcap.py`
  - Handles reading packets from `.pcap`/`.pcapng` files using Scapy `PcapReader`.
  - Extracts packet fields into `PacketSummary` records.
  - Skips unsupported/non-IP packets cleanly.

- `netsentry/live.py`
  - Handles optional live packet capture mode using Scapy sniffing.
  - Converts captured packets into `PacketSummary` records.
  - Note: on Windows this typically requires Npcap/WinPcap-compatible drivers and capture permissions.
  - Example usage:
    - `python -m netsentry --live --count 100 --timeout 15 --json live_summary.json`

- `netsentry/aggregate.py`
  - Contains aggregation utilities for analysis:
    - Time-bucket indexing
    - Per-window packet/byte stats
    - Top talkers by packet count/byte volume
    - Protocol distribution counts

- `netsentry/detect.py`
  - Rule-based detection engine: `detect_alerts(summaries)` returns a list of `Alert` objects (see `netsentry/alerts.py`).
  - Runs on the full `PacketSummary` stream after capture; TCP packets include `tcp_flags` from Scapy for SYN-only classification (SYN set, ACK clear).
  - Uses `netsentry.features.bucket_index` for SYN-flood time bucketing alongside whole-capture heuristics.
  - Implemented rules (thresholds are named constants at the top of the module):
    - **Port scan (`port_scan_tcp`):** many distinct TCP destination ports from one source IP to a single destination IP (vertical scan heuristic).
    - **SYN flood (`syn_flood_syn_only`):** high count of SYN-only packets toward the same destination IP:port within short (~1s) windows.
    - **DNS (`dns_udp_volume`, `dns_large_udp_payload`):** high UDP/53 volume between a client/resolver pair; oversized UDP/53 payloads (possible tunneling).
    - **Brute-force style (`brute_force_tcp_heuristic`):** many TCP packets from one client to a sensitive destination port (SSH, RDP, SMB, common DB ports, etc.).
  - Invoked automatically by `python -m netsentry …`; alerts are printed in the text summary and included in `--json` output.

- `netsentry/persist.py`
  - File writers for full-summary JSON, rolling window CSV/JSONL, and **alert export** (`persist_alerts`): `.json`, `.jsonl`, `.csv`, or `.sqlite`/`.db` (append-only SQLite with WAL).

- `netsentry/report.py`
  - Converts processed results into human-readable and JSON-friendly summaries.
  - Prints concise terminal output and writes full structured output to JSON when requested.

#############################################################################

Scripts Directory (Current Implementation)

The `scripts/` directory contains helper utilities for local testing and demos:

- `scripts/gen_sample_pcap.py`
  - Generates a small synthetic `.pcap` with predictable packet timing and traffic mix.
  - Useful for quick end-to-end validation without needing live capture.
  - Example usage:
    - `python scripts/gen_sample_pcap.py -o sample.pcap`

- `scripts/gen_demo_pcaps.py`
  - Writes one synthetic `.pcap` per detection rule (port scan, SYN flood, DNS volume, large DNS/UDP, SSH brute-force heuristic), using the same numeric thresholds as `netsentry/detect.py`.
  - Optional self-check: `--verify` runs `detect_alerts` on each file and prints `OK` / `FAIL`.
  - Example:
    - `python scripts/gen_demo_pcaps.py --output-dir demo_pcaps --verify`

Detection demo scenarios (reports / screenshots)

Generate the pcaps once from the project root:

- `python scripts/gen_demo_pcaps.py --output-dir demo_pcaps`

Re-run the built-in assertion (optional):

- `python scripts/gen_demo_pcaps.py --output-dir demo_pcaps --verify`

Then run NetSentry on each file. The **expected `rule_id`** (exactly one alert per demo pcap) is:

| Pcap | Expected `rule_id` | Example command |
|------|-------------------|-----------------|
| `demo_pcaps/demo_port_scan.pcap` | `port_scan_tcp` | `python -m netsentry demo_pcaps/demo_port_scan.pcap` |
| `demo_pcaps/demo_syn_flood.pcap` | `syn_flood_syn_only` | `python -m netsentry demo_pcaps/demo_syn_flood.pcap` |
| `demo_pcaps/demo_dns_volume.pcap` | `dns_udp_volume` | `python -m netsentry demo_pcaps/demo_dns_volume.pcap` |
| `demo_pcaps/demo_dns_large.pcap` | `dns_large_udp_payload` | `python -m netsentry demo_pcaps/demo_dns_large.pcap` |
| `demo_pcaps/demo_brute_force_ssh.pcap` | `brute_force_tcp_heuristic` | `python -m netsentry demo_pcaps/demo_brute_force_ssh.pcap` |

To capture alerts for the write-up or a dashboard mock:

- `python -m netsentry demo_pcaps/demo_port_scan.pcap --alerts-out demo_pcaps/alerts_port_scan.jsonl`

(Thresholds live in `netsentry/detect.py`; `gen_demo_pcaps.py` imports them so demos stay in sync if you tune rules.)

Rolling Window Export (Debug/Dashboard Reuse)

- You can export time-window bucket stats directly to a simple file:
  - JSON lines:
    - python -m netsentry sample.pcap --window-stats-out window_stats.jsonl
  - CSV:
    - python -m netsentry sample.pcap --window-stats-out window_stats.csv
- Output columns/fields:
  - window_sec, bucket_start_epoch, bucket_index, packets, bytes

Alert export (dashboard / audit log)

- Persist detection alerts from any run:
  - JSON:
    - `python -m netsentry sample.pcap --alerts-out alerts.json`
  - JSON lines (one alert per line, easy to tail or ingest):
    - `python -m netsentry sample.pcap --alerts-out alerts.jsonl`
  - CSV:
    - `python -m netsentry sample.pcap --alerts-out alerts.csv`
  - SQLite (append-only; suitable for a Flask app reading historical alerts):
    - `python -m netsentry sample.pcap --alerts-out netsentry_alerts.sqlite`
- Each row includes: `ingest_wall` (when the export ran), `source` (absolute pcap path or `live`), packet-time `ts_epoch`, `severity`, `rule_id`, `description`, `src_ip`, `dst_ip`.
