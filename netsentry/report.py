from __future__ import annotations

import json
from typing import Any, Sequence, TextIO

from netsentry.aggregate import (
    build_window_stats,
    proto_counts,
    top_talkers_by_bytes,
    top_talkers_by_packets,
)
from netsentry.records import PacketSummary


def summarize_pipeline(
    summaries: Sequence[PacketSummary],
    window_sizes_sec: tuple[float, float] = (1.0, 60.0),
) -> dict[str, Any]:
    """Build one structured object for text output and JSON export."""
    windows: list[dict[str, Any]] = []
    for w in window_sizes_sec:
        st = build_window_stats(summaries, w)
        windows.append(
            {
                "window_sec": st.window_sec,
                "buckets": [
                    {
                        # Convert bucket index back to the bucket's start epoch.
                        "bucket_start_epoch": b * st.window_sec,
                        "bucket_index": b,
                        "packets": st.packet_counts[b],
                        "bytes": st.byte_counts[b],
                    }
                    for b in st.packet_counts
                ],
            }
        )

    return {
        "total_packets": len(summaries),
        "protocols": proto_counts(summaries),
        "top_talkers_packets": [
            {"ip": ip, "packets": cnt} for ip, cnt in top_talkers_by_packets(summaries, 10)
        ],
        "top_talkers_bytes": [
            {"ip": ip, "bytes": cnt} for ip, cnt in top_talkers_by_bytes(summaries, 10)
        ],
        "time_windows": windows,
    }


def print_summary_text(data: dict[str, Any], out: TextIO) -> None:
    """Pretty terminal summary for quick human validation."""
    out.write(f"Total packets (IP): {data['total_packets']}\n")
    out.write("Protocols:\n")
    for name, cnt in data["protocols"].items():
        out.write(f"  {name}: {cnt}\n")

    out.write("Top talkers (packets):\n")
    for row in data["top_talkers_packets"][:5]:
        out.write(f"  {row['ip']}: {row['packets']}\n")

    out.write("Top talkers (bytes):\n")
    for row in data["top_talkers_bytes"][:5]:
        out.write(f"  {row['ip']}: {row['bytes']}\n")

    for tw in data["time_windows"]:
        w = tw["window_sec"]
        out.write(f"Time windows ({w}s): {len(tw['buckets'])} buckets\n")
        for b in tw["buckets"][:8]:
            out.write(
                f"  start={b['bucket_start_epoch']:.3f}s idx={b['bucket_index']}: "
                f"packets={b['packets']} bytes={b['bytes']}\n"
            )
        if len(tw["buckets"]) > 8:
            out.write(f"  ... ({len(tw['buckets']) - 8} more buckets)\n")


def write_summary_json(data: dict[str, Any], path: str) -> None:
    """Persist structured summary for later analysis or dashboard use."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
