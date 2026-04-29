from __future__ import annotations

import os
from typing import Iterator

from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from netsentry.records import PacketSummary

_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


def summarize_packet(pkt: Packet) -> PacketSummary | None:
    """Extract normalized fields from IPv4/IPv6 packets."""
    ip4 = pkt.getlayer(IP)
    ip6 = pkt.getlayer(IPv6)
    if ip4 is not None:
        src_ip, dst_ip = ip4.src, ip4.dst
        proto_num = int(ip4.proto)
        payload = ip4.payload
    elif ip6 is not None:
        src_ip, dst_ip = ip6.src, ip6.dst
        proto_num = int(ip6.nh)
        payload = ip6.payload
    else:
        return None

    src_port: int | None = None
    dst_port: int | None = None
    if isinstance(payload, TCP):
        src_port, dst_port = int(payload.sport), int(payload.dport)
    elif isinstance(payload, UDP):
        src_port, dst_port = int(payload.sport), int(payload.dport)

    return PacketSummary(
        ts_epoch=float(pkt.time),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        proto_num=proto_num,
        proto_name=_PROTO_NAMES.get(proto_num, f"proto_{proto_num}"),
        size_bytes=len(pkt),
    )


def iter_packet_summaries(pcap_path: str) -> Iterator[PacketSummary]:
    """Stream packet summaries from a pcap/pcapng file."""
    path = os.path.abspath(pcap_path)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"pcap not found: {path}")

    reader = PcapReader(path)
    try:
        for pkt in reader:
            if pkt is None:
                continue
            summary = summarize_packet(pkt)
            if summary is not None:
                yield summary
    finally:
        reader.close()
