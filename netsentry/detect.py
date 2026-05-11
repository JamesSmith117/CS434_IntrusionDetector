from __future__ import annotations

"""Rule-based detection for common suspicious patterns (offline full-trace heuristics)."""

from collections import defaultdict
from typing import Sequence

from netsentry.alerts import Alert
from netsentry.features import bucket_index
from netsentry.records import PacketSummary

# --- Tunable thresholds (interpretable rule knobs) ---

# Vertical TCP port scan: many distinct destination ports to the same host pair.
PORT_SCAN_MIN_UNIQUE_TCP_DPORTS = 12

# SYN flood: many handshake-only SYNs toward the same service in a short window.
SYN_FLOOD_WINDOW_SEC = 1.0
SYN_FLOOD_MIN_SYN_PACKETS = 40

# DNS: excessive UDP/53 volume between a client and resolver in one capture.
DNS_PAIR_UDP53_MIN_PACKETS = 80

# DNS: unusually large UDP payloads to port 53 (possible tunneling / exfil).
DNS_LARGE_UDP_BYTES = 512

# Brute-force style: many TCP packets to a sensitive service port from one client.
BF_TCP_PACKETS_MIN = 25
BF_SENSITIVE_DST_PORTS = frozenset(
    {21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 6379}
)

_PROTO_TCP = 6
_PROTO_UDP = 17
_TCP_SYN = 0x02
_TCP_ACK = 0x10


def _is_syn_only(tcp_flags: int | None) -> bool:
    if tcp_flags is None:
        return False
    return bool(tcp_flags & _TCP_SYN) and not (tcp_flags & _TCP_ACK)


def detect_alerts(summaries: Sequence[PacketSummary]) -> list[Alert]:
    """Run all rules; returns alerts sorted by time."""
    if not summaries:
        return []
    alerts: list[Alert] = []
    alerts.extend(_port_scan_tcp_many_dst_ports(summaries))
    alerts.extend(_syn_flood_by_bucket(summaries))
    alerts.extend(_dns_volume_and_large_udp(summaries))
    alerts.extend(_brute_force_tcp_heuristic(summaries))
    alerts.sort(key=lambda a: a.ts_epoch)
    return alerts


def _port_scan_tcp_many_dst_ports(summaries: Sequence[PacketSummary]) -> list[Alert]:
    """Many distinct TCP destination ports from one source to a single target."""
    by_pair: dict[tuple[str, str], set[int]] = defaultdict(set)
    last_ts: dict[tuple[str, str], float] = defaultdict(float)
    for s in summaries:
        if s.proto_num != _PROTO_TCP or s.src_ip is None or s.dst_ip is None:
            continue
        if s.dst_port is None:
            continue
        key = (s.src_ip, s.dst_ip)
        by_pair[key].add(s.dst_port)
        if s.ts_epoch >= last_ts[key]:
            last_ts[key] = s.ts_epoch

    out: list[Alert] = []
    for (src, dst), ports in by_pair.items():
        n = len(ports)
        if n < PORT_SCAN_MIN_UNIQUE_TCP_DPORTS:
            continue
        out.append(
            Alert(
                ts_epoch=last_ts[(src, dst)],
                severity="high",
                rule_id="port_scan_tcp",
                description=(
                    f"TCP vertical scan heuristic: {n} distinct destination ports "
                    f"from {src} toward {dst} (threshold {PORT_SCAN_MIN_UNIQUE_TCP_DPORTS})"
                ),
                src_ip=src,
                dst_ip=dst,
            )
        )
    return out


def _syn_flood_by_bucket(summaries: Sequence[PacketSummary]) -> list[Alert]:
    """High rate of SYN-only packets toward the same destination IP:port."""
    counts: dict[tuple[str, int, int], int] = defaultdict(int)
    max_ts: dict[tuple[str, int, int], float] = defaultdict(float)

    for s in summaries:
        if not _is_syn_only(s.tcp_flags) or s.dst_ip is None or s.dst_port is None:
            continue
        b = bucket_index(s.ts_epoch, SYN_FLOOD_WINDOW_SEC)
        key = (s.dst_ip, s.dst_port, b)
        counts[key] += 1
        if s.ts_epoch >= max_ts[key]:
            max_ts[key] = s.ts_epoch

    out: list[Alert] = []
    for key, cnt in counts.items():
        if cnt < SYN_FLOOD_MIN_SYN_PACKETS:
            continue
        dst_ip, dst_port, b = key
        start = b * SYN_FLOOD_WINDOW_SEC
        out.append(
            Alert(
                ts_epoch=max_ts[key],
                severity="high",
                rule_id="syn_flood_syn_only",
                description=(
                    f"SYN flood heuristic: {cnt} SYN-only packets to {dst_ip}:{dst_port} "
                    f"within ~{SYN_FLOOD_WINDOW_SEC:g}s window starting {start:g}s "
                    f"(threshold {SYN_FLOOD_MIN_SYN_PACKETS})"
                ),
                src_ip=None,
                dst_ip=dst_ip,
            )
        )
    return out


def _dns_volume_and_large_udp(summaries: Sequence[PacketSummary]) -> list[Alert]:
    """DNS query flood between a pair and oversized UDP/53 payloads."""
    pair_counts: dict[tuple[str, str], int] = defaultdict(int)
    pair_last_ts: dict[tuple[str, str], float] = defaultdict(float)
    large_udp_seen: set[tuple[str, str]] = set()

    out: list[Alert] = []
    for s in summaries:
        if s.proto_num != _PROTO_UDP or s.dst_port != 53:
            continue
        if s.src_ip is None or s.dst_ip is None:
            continue

        pair_key = (s.src_ip, s.dst_ip)
        if s.size_bytes > DNS_LARGE_UDP_BYTES and pair_key not in large_udp_seen:
            large_udp_seen.add(pair_key)
            out.append(
                Alert(
                    ts_epoch=s.ts_epoch,
                    severity="medium",
                    rule_id="dns_large_udp_payload",
                    description=(
                        f"Large UDP/53 packet ({s.size_bytes} bytes) from {s.src_ip} to "
                        f"{s.dst_ip} (threshold {DNS_LARGE_UDP_BYTES} bytes)"
                    ),
                    src_ip=s.src_ip,
                    dst_ip=s.dst_ip,
                )
            )

        key = (s.src_ip, s.dst_ip)
        pair_counts[key] += 1
        if s.ts_epoch >= pair_last_ts[key]:
            pair_last_ts[key] = s.ts_epoch

    for key, cnt in pair_counts.items():
        if cnt < DNS_PAIR_UDP53_MIN_PACKETS:
            continue
        src, dst = key
        out.append(
            Alert(
                ts_epoch=pair_last_ts[key],
                severity="medium",
                rule_id="dns_udp_volume",
                description=(
                    f"High UDP/53 volume: {cnt} packets between {src} and {dst} "
                    f"(threshold {DNS_PAIR_UDP53_MIN_PACKETS})"
                ),
                src_ip=src,
                dst_ip=dst,
            )
        )
    return out


def _brute_force_tcp_heuristic(summaries: Sequence[PacketSummary]) -> list[Alert]:
    """Many TCP packets toward a sensitive destination port from one source."""
    counts: dict[tuple[str, str, int], int] = defaultdict(int)
    last_ts: dict[tuple[str, str, int], float] = defaultdict(float)

    for s in summaries:
        if s.proto_num != _PROTO_TCP or s.src_ip is None or s.dst_ip is None:
            continue
        if s.dst_port is None or s.dst_port not in BF_SENSITIVE_DST_PORTS:
            continue
        key = (s.src_ip, s.dst_ip, s.dst_port)
        counts[key] += 1
        if s.ts_epoch >= last_ts[key]:
            last_ts[key] = s.ts_epoch

    out: list[Alert] = []
    for key, cnt in counts.items():
        if cnt < BF_TCP_PACKETS_MIN:
            continue
        src, dst, dport = key
        out.append(
            Alert(
                ts_epoch=last_ts[key],
                severity="medium",
                rule_id="brute_force_tcp_heuristic",
                description=(
                    f"Many TCP packets ({cnt}) from {src} to {dst}:{dport} "
                    f"(threshold {BF_TCP_PACKETS_MIN}; sensitive-port heuristic)"
                ),
                src_ip=src,
                dst_ip=dst,
            )
        )
    return out
