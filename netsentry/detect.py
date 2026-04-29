from __future__ import annotations

from typing import Sequence

from netsentry.alerts import Alert
from netsentry.records import PacketSummary


def detect_alerts(_summaries: Sequence[PacketSummary]) -> list[Alert]:
    """
    Rule engine boundary.
    Week 3-4 rules should live here and return Alert objects.
    """
    return []
