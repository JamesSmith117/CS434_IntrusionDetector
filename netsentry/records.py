from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class PacketSummary:
    """Normalized per-packet record shared across pipeline stages."""

    # Unix epoch timestamp from packet capture metadata.
    ts_epoch: float
    # Source and destination IP addresses (IPv4 or IPv6).
    src_ip: Optional[str]
    dst_ip: Optional[str]
    # Transport-layer ports when available (TCP/UDP), else None.
    src_port: Optional[int]
    dst_port: Optional[int]
    # Numeric protocol id and readable label for reporting.
    proto_num: Optional[int]
    proto_name: str
    # Packet size in bytes.
    size_bytes: int
