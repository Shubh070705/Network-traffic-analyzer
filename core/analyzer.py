"""
core/analyzer.py

Consumes raw Scapy packets from the capture queue, parses them into
PacketRecord objects (metadata only — never payload), and fans them out to:
  - the statistics engine
  - the detection engine
  - the CSV/PCAP exporters
  - an in-memory ring buffer for the "live packet stream" dashboard panel

Runs in its own thread so a slow dashboard render never blocks capture.
"""

from __future__ import annotations

import logging
import queue
import threading
from collections import deque
from time import time
from typing import Callable, Deque, Optional

from core.models import PacketRecord, Protocol
from core.statistics import StatisticsEngine
from detection.engine import DetectionEngine

logger = logging.getLogger("nta.analyzer")


def parse_packet(pkt, now: Optional[float] = None) -> Optional[PacketRecord]:
    """
    Convert a raw Scapy packet into a PacketRecord.

    Returns None for packets that carry no usable IP-layer metadata (e.g.
    pure link-layer frames like ARP), so callers can safely skip them.
    Malformed or partially-parsed packets never raise — worst case they are
    skipped, which keeps the pipeline resilient to odd traffic.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore
    except ImportError:
        return None

    if now is None:
        now = time()

    try:
        if not pkt.haslayer(IP):
            return None

        ip_layer = pkt[IP]
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
        ttl = int(ip_layer.ttl) if ip_layer.ttl is not None else None
        size = len(pkt)

        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        tcp_flags: Optional[str] = None
        protocol = Protocol.OTHER

        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            protocol = Protocol.TCP
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            try:
                tcp_flags = str(tcp_layer.flags)
            except Exception:  # noqa: BLE001
                tcp_flags = None
        elif pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            protocol = Protocol.UDP
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)
        elif pkt.haslayer(ICMP):
            protocol = Protocol.ICMP

        return PacketRecord(
            timestamp=now,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            size=size,
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=tcp_flags,
            ttl=ttl,
        )
    except Exception:  # noqa: BLE001 - never let a malformed packet kill the pipeline
        logger.debug("Skipping malformed packet during parsing.", exc_info=True)
        return None


class AnalyzerThread(threading.Thread):
    """
    Pulls raw packets off `packet_queue`, parses them, and feeds the
    statistics engine, detection engine, live stream buffer, and any
    registered sink callbacks (e.g. CSV/PCAP exporters).
    """

    def __init__(
        self,
        packet_queue: "queue.Queue",
        statistics: StatisticsEngine,
        detection: DetectionEngine,
        live_stream_maxlen: int = 200,
        on_record: Optional[Callable[[PacketRecord], None]] = None,
        on_raw_packet: Optional[Callable[[object], None]] = None,
    ) -> None:
        super().__init__(name="AnalyzerThread", daemon=True)
        self.packet_queue = packet_queue
        self.statistics = statistics
        self.detection = detection
        self.live_stream: Deque[PacketRecord] = deque(maxlen=live_stream_maxlen)
        self.on_record = on_record
        self.on_raw_packet = on_raw_packet
        self.stop_event = threading.Event()
        self._lock = threading.Lock()
        self._processed = 0
        self._malformed = 0

    def stop(self) -> None:
        self.stop_event.set()

    @property
    def processed_count(self) -> int:
        return self._processed

    @property
    def malformed_count(self) -> int:
        return self._malformed

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                pkt = self.packet_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if self.on_raw_packet is not None:
                try:
                    self.on_raw_packet(pkt)
                except Exception:  # noqa: BLE001
                    logger.debug("on_raw_packet sink raised.", exc_info=True)

            record = parse_packet(pkt)
            if record is None:
                self._malformed += 1
                continue

            self._processed += 1

            with self._lock:
                self.live_stream.append(record)

            self.statistics.record(record)
            self.detection.observe(record)

            if self.on_record is not None:
                try:
                    self.on_record(record)
                except Exception:  # noqa: BLE001
                    logger.debug("on_record sink raised.", exc_info=True)

    def snapshot_live_stream(self) -> list:
        with self._lock:
            return list(self.live_stream)
