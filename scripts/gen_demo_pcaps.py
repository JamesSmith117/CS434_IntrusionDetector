"""
Generate synthetic pcaps that trigger each NetSentry detection rule (for reports / screenshots).

Run from the project root (same as other scripts):

  python scripts/gen_demo_pcaps.py
  python scripts/gen_demo_pcaps.py --output-dir demo_pcaps --verify

Outputs are *.pcap (gitignored). Thresholds match netsentry.detect constants.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Repo root on sys.path when invoked as `python scripts/gen_demo_pcaps.py`
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scapy.all import Ether, IP, Raw, TCP, UDP, wrpcap  # noqa: E402

from netsentry import detect as det  # noqa: E402


def _write_port_scan(path: Path, base: float) -> None:
    n = det.PORT_SCAN_MIN_UNIQUE_TCP_DPORTS + 3
    pkts = []
    for i in range(n):
        pkt = (
            Ether()
            / IP(src="10.10.1.50", dst="10.10.1.1")
            / TCP(sport=40000 + i, dport=2000 + i, flags="S")
        )
        pkt.time = base + i * 0.02
        pkts.append(pkt)
    wrpcap(str(path), pkts)


def _write_syn_flood(path: Path, base: float) -> None:
    n = det.SYN_FLOOD_MIN_SYN_PACKETS + 8
    pkts = []
    for i in range(n):
        pkt = (
            Ether()
            / IP(src="10.10.2.10", dst="10.10.2.1")
            / TCP(sport=50000 + i, dport=80, flags="S")
        )
        # Same 1s bucket: spread within [base, base + 0.9)
        pkt.time = base + i * (0.9 / max(n, 2))
        pkts.append(pkt)
    wrpcap(str(path), pkts)


def _write_dns_volume(path: Path, base: float) -> None:
    n = det.DNS_PAIR_UDP53_MIN_PACKETS + 10
    pkts = []
    for i in range(n):
        pkt = (
            Ether()
            / IP(src="10.10.3.1", dst="10.10.3.2")
            / UDP(sport=52000 + (i % 5000), dport=53)
            / Raw(load=b"\x00\x01" + b"\x07example\x03com\x00\x00\x01\x00\x01")
        )
        pkt.time = base + i * 0.001
        pkts.append(pkt)
    wrpcap(str(path), pkts)


def _write_dns_large(path: Path, base: float) -> None:
    # Full frame length must exceed DNS_LARGE_UDP_BYTES (see pcap len(pkt)).
    payload = b"Q" * max(600, det.DNS_LARGE_UDP_BYTES + 50)
    pkt = (
        Ether()
        / IP(src="10.10.5.1", dst="10.10.5.2")
        / UDP(sport=55555, dport=53)
        / Raw(load=payload)
    )
    pkt.time = base
    wrpcap(str(path), [pkt])


def _write_brute_force_ssh(path: Path, base: float) -> None:
    n = det.BF_TCP_PACKETS_MIN + 5
    pkts = []
    for i in range(n):
        pkt = (
            Ether()
            / IP(src="10.10.4.1", dst="10.10.4.2")
            / TCP(sport=51000 + i, dport=22, flags="A")
        )
        pkt.time = base + i * 0.05
        pkts.append(pkt)
    wrpcap(str(path), pkts)


def _verify(out_dir: Path) -> int:
    from netsentry.detect import detect_alerts
    from netsentry.pcap import iter_packet_summaries

    cases: list[tuple[str, frozenset[str]]] = [
        ("demo_port_scan.pcap", frozenset({"port_scan_tcp"})),
        ("demo_syn_flood.pcap", frozenset({"syn_flood_syn_only"})),
        ("demo_dns_volume.pcap", frozenset({"dns_udp_volume"})),
        ("demo_dns_large.pcap", frozenset({"dns_large_udp_payload"})),
        ("demo_brute_force_ssh.pcap", frozenset({"brute_force_tcp_heuristic"})),
    ]
    failed = 0
    for name, expected in cases:
        path = out_dir / name
        alerts = detect_alerts(list(iter_packet_summaries(str(path))))
        got = frozenset(a.rule_id for a in alerts)
        if got != expected:
            print(f"FAIL {name}: expected {sorted(expected)} got {sorted(got)}", file=sys.stderr)
            failed += 1
        else:
            print(f"OK   {name}: {sorted(got)}")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate demo pcaps for each detection rule.")
    ap.add_argument(
        "--output-dir",
        default="demo_pcaps",
        help="Directory to write demo_*.pcap files (created if missing)",
    )
    ap.add_argument(
        "--verify",
        action="store_true",
        help="After writing, run detection and assert expected rule_ids",
    )
    args = ap.parse_args()

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    base = 1_700_000_000.0

    writers = [
        ("demo_port_scan.pcap", _write_port_scan),
        ("demo_syn_flood.pcap", _write_syn_flood),
        ("demo_dns_volume.pcap", _write_dns_volume),
        ("demo_dns_large.pcap", _write_dns_large),
        ("demo_brute_force_ssh.pcap", _write_brute_force_ssh),
    ]
    for name, fn in writers:
        path = out / name
        fn(path, base)
        print(f"Wrote {path}")

    if args.verify:
        return _verify(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
