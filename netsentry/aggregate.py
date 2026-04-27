from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Iterable, Sequence

from netsentry.records import PacketSummary


def bucket_index(ts_epoch: float, window_sec: float) -> int:
    return int(ts_epoch // window_sec)


@dataclass
class WindowStats:
    window_sec: float
    # bucket_start_epoch -> packet count
    packet_counts: dict[int, int]
    # bucket_start_epoch -> byte sum
    byte_counts: dict[int, int]


def build_window_stats(
    summaries: Iterable[PacketSummary],
    window_sec: float,
) -> WindowStats:
    packet_counts: dict[int, int] = defaultdict(int)
    byte_counts: dict[int, int] = defaultdict(int)
    for s in summaries:
        b = bucket_index(s.ts_epoch, window_sec)
        packet_counts[b] += 1
        byte_counts[b] += s.size_bytes
    return WindowStats(
        window_sec=window_sec,
        packet_counts=dict(sorted(packet_counts.items())),
        byte_counts=dict(sorted(byte_counts.items())),
    )


def top_talkers_by_packets(
    summaries: Sequence[PacketSummary],
    n: int = 10,
) -> list[tuple[str, int]]:
    """Top source IPs by packet count (IPv4/IPv6 string)."""
    c: Counter[str] = Counter()
    for s in summaries:
        if s.src_ip:
            c[s.src_ip] += 1
    return c.most_common(n)


def top_talkers_by_bytes(
    summaries: Sequence[PacketSummary],
    n: int = 10,
) -> list[tuple[str, int]]:
    c: Counter[str] = Counter()
    for s in summaries:
        if s.src_ip:
            c[s.src_ip] += s.size_bytes
    return c.most_common(n)


def proto_counts(summaries: Sequence[PacketSummary]) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for s in summaries:
        out[s.proto_name] += 1
    return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))
