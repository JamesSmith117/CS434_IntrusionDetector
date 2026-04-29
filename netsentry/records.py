from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class PacketSummary:
    """Normalized per-packet fields used by features/reporting."""

    ts_epoch: float
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    proto_num: Optional[int]
    proto_name: str
    size_bytes: int


@dataclass(frozen=True)
class WindowBucket:
    """Aggregated packet/byte totals for one fixed-size time bucket."""

    window_sec: float
    bucket_index: int
    bucket_start_epoch: float
    packets: int
    bytes: int


@dataclass(frozen=True)
class FlowKey:
    """Basic flow-ish key for future detection features."""

    src_ip: str
    dst_ip: str
    dst_port: int
