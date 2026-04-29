from __future__ import annotations

from collections import Counter, defaultdict
from typing import Sequence

from netsentry.records import PacketSummary, WindowBucket


def bucket_index(ts_epoch: float, window_sec: float) -> int:
    return int(ts_epoch // window_sec)


def build_window_buckets(
    summaries: Sequence[PacketSummary],
    window_sec: float,
) -> list[WindowBucket]:
    packet_counts: dict[int, int] = defaultdict(int)
    byte_counts: dict[int, int] = defaultdict(int)
    for s in summaries:
        b = bucket_index(s.ts_epoch, window_sec)
        packet_counts[b] += 1
        byte_counts[b] += s.size_bytes

    buckets: list[WindowBucket] = []
    for b in sorted(packet_counts):
        buckets.append(
            WindowBucket(
                window_sec=window_sec,
                bucket_index=b,
                bucket_start_epoch=b * window_sec,
                packets=packet_counts[b],
                bytes=byte_counts[b],
            )
        )
    return buckets


def top_talkers_by_packets(
    summaries: Sequence[PacketSummary],
    n: int = 10,
) -> list[tuple[str, int]]:
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
