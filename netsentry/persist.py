from __future__ import annotations

import csv
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Sequence

from netsentry.alerts import Alert


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


_ALERT_CSV_FIELDS = [
    "ingest_wall",
    "source",
    "ts_epoch",
    "severity",
    "rule_id",
    "description",
    "src_ip",
    "dst_ip",
]


def alerts_as_rows(
    alerts: Sequence[Alert],
    *,
    ingest_wall: float,
    source: str | None,
) -> list[dict[str, Any]]:
    """Flatten alerts for CSV / JSON / JSONL export."""
    src = source if source is not None else ""
    return [
        {
            "ingest_wall": ingest_wall,
            "source": src,
            "ts_epoch": a.ts_epoch,
            "severity": a.severity,
            "rule_id": a.rule_id,
            "description": a.description,
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
        }
        for a in alerts
    ]


def persist_alerts(
    path: str,
    alerts: Sequence[Alert],
    *,
    source: str | None = None,
) -> None:
    """
    Write alerts to a file; format is chosen from the path suffix.

    - ``.json`` — single JSON object ``{"alerts": [ ... ]}``
    - ``.jsonl`` — one JSON object per line
    - ``.csv`` — CSV with header
    - ``.sqlite`` / ``.db`` — append rows to SQLite (creates schema if needed)
    """
    out = Path(path)
    suffix = out.suffix.lower()
    ingest_wall = time.time()

    if suffix == ".json":
        write_json(path, {"alerts": alerts_as_rows(alerts, ingest_wall=ingest_wall, source=source)})
        return
    if suffix == ".jsonl":
        write_jsonl(path, alerts_as_rows(alerts, ingest_wall=ingest_wall, source=source))
        return
    if suffix == ".csv":
        rows = alerts_as_rows(alerts, ingest_wall=ingest_wall, source=source)
        if not rows:
            with open(path, "w", encoding="utf-8", newline="") as f:
                csv.DictWriter(f, fieldnames=_ALERT_CSV_FIELDS).writeheader()
        else:
            write_csv(path, rows)
        return
    if suffix in (".sqlite", ".db"):
        append_alerts_sqlite(path, alerts, ingest_wall=ingest_wall, source=source)
        return

    raise ValueError(
        f"Unsupported alerts export suffix {suffix!r}; "
        "use .json, .jsonl, .csv, .sqlite, or .db"
    )


_SQLITE_DDL = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ingest_wall REAL NOT NULL,
    source TEXT,
    ts_epoch REAL NOT NULL,
    severity TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    description TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT
);
"""


def append_alerts_sqlite(
    path: str,
    alerts: Sequence[Alert],
    *,
    ingest_wall: float,
    source: str | None = None,
) -> None:
    """Append alert rows; creates the database file and table on first use."""
    conn = sqlite3.connect(path)
    try:
        conn.execute(_SQLITE_DDL)
        conn.execute("PRAGMA journal_mode=WAL;")
        rows = [
            (
                ingest_wall,
                source if source is not None else "",
                a.ts_epoch,
                a.severity,
                a.rule_id,
                a.description,
                a.src_ip,
                a.dst_ip,
            )
            for a in alerts
        ]
        conn.executemany(
            "INSERT INTO alerts (ingest_wall, source, ts_epoch, severity, rule_id, description, src_ip, dst_ip) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
    finally:
        conn.close()


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
