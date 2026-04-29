from __future__ import annotations

"""Backward-compatible exports; new code should import netsentry.features."""

from netsentry.features import (
    bucket_index,
    build_window_buckets,
    proto_counts,
    top_talkers_by_bytes,
    top_talkers_by_packets,
)

__all__ = [
    "bucket_index",
    "build_window_buckets",
    "top_talkers_by_packets",
    "top_talkers_by_bytes",
    "proto_counts",
]
