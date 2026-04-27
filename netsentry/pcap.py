from __future__ import annotations

import os
from typing import Iterator

from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from netsentry.records import PacketSummary

# IANA protocol numbers we surface by name
_PROTO_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
}


def _layer_ts(pkt: Packet) -> float:
    t = float(pkt.time)
    return t


def _summarize_packet(pkt: Packet) -> PacketSummary | None:
    """Return a summary for IP-bearing packets; skip others."""
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

    name = _PROTO_NAMES.get(proto_num, f"proto_{proto_num}")
    return PacketSummary(
        ts_epoch=_layer_ts(pkt),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        proto_num=proto_num,
        proto_name=name,
        size_bytes=len(pkt),
    )


def iter_packet_summaries(pcap_path: str) -> Iterator[PacketSummary]:
    """
    Stream packets from a pcap/pcapng file without loading the whole file.
    Yields PacketSummary for each IPv4/IPv6 packet; non-IP link types are skipped
    if they have no IP layer.
    """
    path = os.path.abspath(pcap_path)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"pcap not found: {path}")

    reader = PcapReader(path)
    try:
        for pkt in reader:
            if pkt is None:
                continue
            summary = _summarize_packet(pkt)
            if summary is not None:
                yield summary
    finally:
        reader.close()
