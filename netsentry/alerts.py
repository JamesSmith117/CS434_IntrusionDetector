from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Alert:
    """Detection output contract shared by rules and report layers."""

    ts_epoch: float
    severity: str
    rule_id: str
    description: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
