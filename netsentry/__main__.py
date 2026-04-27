from __future__ import annotations

import argparse
import sys

from netsentry.pcap import iter_packet_summaries
from netsentry.report import print_summary_text, summarize_pipeline, write_summary_json


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Offline pcap pipeline: extract fields, time buckets, summary."
    )
    p.add_argument("pcap", help="Path to .pcap or .pcapng")
    p.add_argument(
        "--json",
        metavar="PATH",
        help="Write full summary as JSON",
    )
    p.add_argument(
        "--windows",
        default="1,60",
        help="Comma-separated time window sizes in seconds (default: 1,60)",
    )
    args = p.parse_args(argv)

    try:
        sizes = tuple(float(x.strip()) for x in args.windows.split(",") if x.strip())
    except ValueError:
        print("Invalid --windows: use comma-separated numbers, e.g. 1,60", file=sys.stderr)
        return 2
    if not sizes or any(w <= 0 for w in sizes):
        print("Window sizes must be positive.", file=sys.stderr)
        return 2

    summaries = list(iter_packet_summaries(args.pcap))
    data = summarize_pipeline(summaries, window_sizes_sec=sizes)
    print_summary_text(data, sys.stdout)

    if args.json:
        write_summary_json(data, args.json)
        print(f"Wrote JSON summary to {args.json}", file=sys.stdout)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
