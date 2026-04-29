from __future__ import annotations

from typing import List, Optional

from scapy.all import sniff

from netsentry.pcap import summarize_packet
from netsentry.records import PacketSummary


def capture_live_summaries(
    interface: Optional[str] = None,
    count: int = 50,
    timeout: float = 10.0,
    bpf_filter: Optional[str] = None,
) -> list[PacketSummary]:
    """
    Capture live packets and return normalized summaries.
    Requires OS packet-capture permissions and a working capture provider.
    """
    summaries: List[PacketSummary] = []

    def _on_packet(pkt) -> None:
        s = summarize_packet(pkt)
        if s is not None:
            summaries.append(s)

    sniff(
        iface=interface,
        count=count,
        timeout=timeout,
        filter=bpf_filter,
        prn=_on_packet,
        store=False,
    )
    return summaries
