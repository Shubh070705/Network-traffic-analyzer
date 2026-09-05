"""
core/statistics.py

Thread-safe rolling-window traffic statistics: packets/sec, bytes/sec,
average packet size, protocol ratios, top hosts, and top traffic
generators (by bytes). Uses a deque of (timestamp, PacketRecord) pairs and
prunes anything older than `window_seconds` on every read/write, so rates
reflect recent activity rather than the whole session.

Cumulative (session-lifetime) counters are tracked separately so the
dashboard can show both "right now" rates and running totals.
"""

from __future__ import annotations

import threading
from collections import Counter, deque
from time import time
from typing import Deque, Tuple

from core.models import PacketRecord, Protocol, StatsSnapshot


class StatisticsEngine:
    def __init__(self, window_seconds: float = 5.0) -> None:
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._window: Deque[Tuple[float, PacketRecord]] = deque()

        # Session-lifetime cumulative counters.
        self._total_packets = 0
        self._total_bytes = 0
        self._protocol_counts: Counter = Counter({p.value: 0 for p in Protocol})
        self._host_packet_counts: Counter = Counter()
        self._host_byte_counts: Counter = Counter()

    def record(self, record: PacketRecord) -> None:
        with self._lock:
            self._window.append((record.timestamp, record))
            self._total_packets += 1
            self._total_bytes += record.size
            self._protocol_counts[record.protocol.value] += 1
            self._host_packet_counts[record.src_ip] += 1
            self._host_packet_counts[record.dst_ip] += 1
            self._host_byte_counts[record.src_ip] += record.size
            self._prune_locked()

    def _prune_locked(self, now: float | None = None) -> None:
        now = now if now is not None else time()
        cutoff = now - self.window_seconds
        while self._window and self._window[0][0] < cutoff:
            self._window.popleft()

    def snapshot(self) -> StatsSnapshot:
        now = time()
        with self._lock:
            self._prune_locked(now)
            window_packets = len(self._window)
            window_bytes = sum(r.size for _, r in self._window)

            elapsed = self.window_seconds
            pps = window_packets / elapsed if elapsed > 0 else 0.0
            bps = window_bytes / elapsed if elapsed > 0 else 0.0
            avg_size = (self._total_bytes / self._total_packets) if self._total_packets else 0.0

            total_proto = sum(self._protocol_counts.values()) or 1
            ratios = {
                proto: (count / total_proto) * 100.0
                for proto, count in self._protocol_counts.items()
            }

            top_hosts = self._host_packet_counts.most_common(10)
            top_talkers = self._host_byte_counts.most_common(10)

            return StatsSnapshot(
                generated_at=now,
                total_packets=self._total_packets,
                total_bytes=self._total_bytes,
                packets_per_second=round(pps, 2),
                bytes_per_second=round(bps, 2),
                average_packet_size=round(avg_size, 2),
                protocol_counts=dict(self._protocol_counts),
                protocol_ratios={k: round(v, 2) for k, v in ratios.items()},
                top_hosts=top_hosts,
                top_talkers=top_talkers,
            )

    def reset(self) -> None:
        with self._lock:
            self._window.clear()
            self._total_packets = 0
            self._total_bytes = 0
            self._protocol_counts = Counter({p.value: 0 for p in Protocol})
            self._host_packet_counts = Counter()
            self._host_byte_counts = Counter()
