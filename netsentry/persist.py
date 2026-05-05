from __future__ import annotations

import csv
import json
from typing import Any


def write_json(path: str, data: dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def write_jsonl(path: str, rows: list[dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, separators=(",", ":")) + "\n")


def write_csv(path: str, rows: list[dict[str, Any]]) -> None:
    if not rows:
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write("")
        return

    fieldnames = list(rows[0].keys())
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def flatten_window_buckets(summary_data: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for window in summary_data.get("time_windows", []):
        window_sec = window.get("window_sec")
        for bucket in window.get("buckets", []):
            rows.append(
                {
                    "window_sec": window_sec,
                    "bucket_start_epoch": bucket.get("bucket_start_epoch"),
                    "bucket_index": bucket.get("bucket_index"),
                    "packets": bucket.get("packets"),
                    "bytes": bucket.get("bytes"),
                }
            )
    return rows
