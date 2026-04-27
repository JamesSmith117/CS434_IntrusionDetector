from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class PacketSummary:
    """Per-packet fields used for aggregation and reporting."""

    ts_epoch: float
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    proto_num: Optional[int]
    proto_name: str
    size_bytes: int
