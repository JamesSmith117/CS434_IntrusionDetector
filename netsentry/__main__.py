from __future__ import annotations

import argparse
import sys

from netsentry.detect import detect_alerts
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
        description="Offline pcap pipeline: extract fields, windows, and report."
    )
    p.add_argument("pcap", help="Path to .pcap or .pcapng")
    p.add_argument("--json", metavar="PATH", help="Write full summary JSON")
    p.add_argument(
        "--windows",
        default="1,60",
        help="Comma-separated window sizes in seconds (default: 1,60)",
    )
    args = p.parse_args(argv)

    try:
        window_sizes = _parse_windows(args.windows)
    except ValueError as err:
        print(str(err), file=sys.stderr)
        return 2

    # Pipeline orchestration only.
    summaries = list(iter_packet_summaries(args.pcap))
    alerts = detect_alerts(summaries)
    data = summarize_pipeline(
        summaries=summaries,
        alerts=alerts,
        window_sizes_sec=window_sizes,
    )
    print_summary_text(data, sys.stdout)

    if args.json:
        write_json(args.json, data)
        print(f"Wrote JSON summary to {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
