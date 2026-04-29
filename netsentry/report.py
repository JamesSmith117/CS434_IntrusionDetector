from __future__ import annotations

from typing import Any, Sequence, TextIO

from netsentry.alerts import Alert
from netsentry.features import (
    build_window_buckets,
    proto_counts,
    top_talkers_by_bytes,
    top_talkers_by_packets,
)
from netsentry.records import PacketSummary


def summarize_pipeline(
    summaries: Sequence[PacketSummary],
    alerts: Sequence[Alert] | None = None,
    window_sizes_sec: tuple[float, ...] = (1.0, 60.0),
) -> dict[str, Any]:
    """Shape a report object from features + alerts."""
    windows: list[dict[str, Any]] = []
    for w in window_sizes_sec:
        buckets = build_window_buckets(summaries, w)
        windows.append(
            {
                "window_sec": w,
                "buckets": [
                    {
                        "bucket_start_epoch": b.bucket_start_epoch,
                        "bucket_index": b.bucket_index,
                        "packets": b.packets,
                        "bytes": b.bytes,
                    }
                    for b in buckets
                ],
            }
        )

    alert_rows = []
    for a in alerts or []:
        alert_rows.append(
            {
                "ts_epoch": a.ts_epoch,
                "severity": a.severity,
                "rule_id": a.rule_id,
                "description": a.description,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
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
        "alerts": alert_rows,
        "time_windows": windows,
    }


def print_summary_text(data: dict[str, Any], out: TextIO) -> None:
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

    out.write(f"Alerts: {len(data.get('alerts', []))}\n")
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
