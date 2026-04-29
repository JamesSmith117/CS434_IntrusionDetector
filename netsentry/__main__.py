from __future__ import annotations

import argparse
import sys

from netsentry.detect import detect_alerts
from netsentry.live import capture_live_summaries
from netsentry.pcap import iter_packet_summaries
from netsentry.persist import write_json
from netsentry.report import print_summary_text, summarize_pipeline


def _parse_windows(raw: str) -> tuple[float, ...]:
    try:
        sizes = tuple(float(x.strip()) for x in raw.split(",") if x.strip())
    except ValueError as exc:
        raise ValueError("Invalid --windows. Example: 1,60") from exc
    if not sizes or any(w <= 0 for w in sizes):
        raise ValueError("Window sizes must be positive")
    return sizes


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="NetSentry pipeline: offline pcap (default) or optional live capture."
    )
    p.add_argument(
        "pcap",
        nargs="?",
        help="Path to .pcap or .pcapng (required unless --live is used)",
    )
    p.add_argument("--json", metavar="PATH", help="Write full summary JSON")
    p.add_argument("--windows", default="1,60", help="Comma-separated window sizes in seconds")
    p.add_argument("--live", action="store_true", help="Use live packet capture mode")
    p.add_argument("--iface", help="Interface name for live capture")
    p.add_argument("--count", type=int, default=50, help="Packets to capture in live mode")
    p.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Capture timeout seconds for live mode",
    )
    p.add_argument("--filter", dest="bpf_filter", help="Optional BPF capture filter")
    args = p.parse_args(argv)

    try:
        window_sizes = _parse_windows(args.windows)
    except ValueError as err:
        print(str(err), file=sys.stderr)
        return 2

    if args.live:
        if args.count <= 0 or args.timeout <= 0:
            print("--count and --timeout must be positive in live mode.", file=sys.stderr)
            return 2
        try:
            summaries = capture_live_summaries(
                interface=args.iface,
                count=args.count,
                timeout=args.timeout,
                bpf_filter=args.bpf_filter,
            )
        except Exception as err:
            print(f"Live capture failed: {err}", file=sys.stderr)
            print(
                "Tip: install Npcap/WinPcap-compatible capture driver on Windows, "
                "or use offline pcap mode.",
                file=sys.stderr,
            )
            return 2
    else:
        if not args.pcap:
            print("pcap path is required unless --live is used.", file=sys.stderr)
            return 2
        summaries = list(iter_packet_summaries(args.pcap))

    alerts = detect_alerts(summaries)
    data = summarize_pipeline(summaries=summaries, alerts=alerts, window_sizes_sec=window_sizes)
    print_summary_text(data, sys.stdout)

    if args.json:
        write_json(args.json, data)
        print(f"Wrote JSON summary to {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
