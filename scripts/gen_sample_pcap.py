"""
Write a tiny synthetic pcap for local testing (outputs are gitignored by *.pcap).

Usage:
  python scripts/gen_sample_pcap.py -o sample.pcap
"""
from __future__ import annotations

import argparse

from scapy.all import Ether, IP, TCP, UDP, wrpcap


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate a minimal pcap for NetSentry demos.")
    ap.add_argument("-o", "--output", default="sample.pcap", help="Output path")
    args = ap.parse_args()

    base = 1_700_000_000.0  # fixed epoch anchor for reproducible bucket boundaries
    pkts = []

    for i in range(5):
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=49152 + i, dport=443)
        pkt.time = base + i * 0.2
        pkts.append(pkt)

    u = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=443, dport=49152)
    u.time = base + 125.0
    pkts.append(u)

    icmp = Ether() / IP(src="10.0.0.3", dst="10.0.0.2", proto=1)
    icmp.time = base + 130.0
    pkts.append(icmp)

    wrpcap(args.output, pkts)
    print(f"Wrote {len(pkts)} packets to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
