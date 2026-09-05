"""
tests/test_analyzer.py

Unit tests for core.statistics and core.analyzer.parse_packet.

These tests avoid real packet capture entirely — they either build
PacketRecord objects directly, or (for parse_packet) build minimal Scapy
packet objects in memory. If Scapy is not importable in the test
environment, the parse_packet tests are skipped rather than failing, since
the rest of the pipeline (statistics, detection) has no hard Scapy
dependency and should still be verifiable.
"""

from __future__ import annotations

import time
import unittest

from core.models import PacketRecord, Protocol
from core.statistics import StatisticsEngine

try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def make_record(
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    protocol=Protocol.TCP,
    size=100,
    src_port=1234,
    dst_port=80,
    tcp_flags="S",
    ttl=64,
    timestamp=None,
):
    return PacketRecord(
        timestamp=timestamp if timestamp is not None else time.time(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        size=size,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        ttl=ttl,
    )


class TestStatisticsEngine(unittest.TestCase):
    def test_empty_snapshot_has_sane_defaults(self):
        engine = StatisticsEngine(window_seconds=5.0)
        snap = engine.snapshot()
        self.assertEqual(snap.total_packets, 0)
        self.assertEqual(snap.total_bytes, 0)
        self.assertEqual(snap.packets_per_second, 0.0)
        self.assertEqual(snap.bytes_per_second, 0.0)
        self.assertEqual(snap.average_packet_size, 0.0)
        self.assertEqual(snap.top_hosts, [])
        self.assertEqual(snap.top_talkers, [])

    def test_recording_updates_totals(self):
        engine = StatisticsEngine(window_seconds=5.0)
        engine.record(make_record(size=100))
        engine.record(make_record(size=200))
        snap = engine.snapshot()
        self.assertEqual(snap.total_packets, 2)
        self.assertEqual(snap.total_bytes, 300)
        self.assertAlmostEqual(snap.average_packet_size, 150.0)

    def test_protocol_ratios_sum_to_roughly_100(self):
        engine = StatisticsEngine(window_seconds=5.0)
        engine.record(make_record(protocol=Protocol.TCP))
        engine.record(make_record(protocol=Protocol.UDP))
        engine.record(make_record(protocol=Protocol.ICMP))
        engine.record(make_record(protocol=Protocol.TCP))
        snap = engine.snapshot()
        total_ratio = sum(snap.protocol_ratios.values())
        self.assertAlmostEqual(total_ratio, 100.0, delta=0.1)
        self.assertGreater(snap.protocol_ratios["TCP"], snap.protocol_ratios["UDP"])

    def test_top_hosts_and_talkers_ranked(self):
        engine = StatisticsEngine(window_seconds=5.0)
        # host_a sends many small packets; host_b sends few big ones.
        for _ in range(5):
            engine.record(make_record(src_ip="host_a", dst_ip="peer", size=10))
        engine.record(make_record(src_ip="host_b", dst_ip="peer", size=5000))

        snap = engine.snapshot()
        top_host_ips = [ip for ip, _ in snap.top_hosts]
        self.assertIn("host_a", top_host_ips)

        top_talker_ips = [ip for ip, _ in snap.top_talkers]
        self.assertEqual(top_talker_ips[0], "host_b")

    def test_window_prunes_old_entries(self):
        engine = StatisticsEngine(window_seconds=1.0)
        old_ts = time.time() - 10.0
        engine.record(make_record(timestamp=old_ts))
        snap = engine.snapshot()
        # The old packet should have been pruned from the rolling window,
        # so packets_per_second should reflect zero recent activity.
        self.assertEqual(snap.packets_per_second, 0.0)
        # But cumulative total should still count it.
        self.assertEqual(snap.total_packets, 1)

    def test_reset_clears_state(self):
        engine = StatisticsEngine(window_seconds=5.0)
        engine.record(make_record())
        engine.reset()
        snap = engine.snapshot()
        self.assertEqual(snap.total_packets, 0)
        self.assertEqual(snap.total_bytes, 0)


@unittest.skipUnless(SCAPY_AVAILABLE, "Scapy not available in this environment.")
class TestParsePacket(unittest.TestCase):
    def test_parses_tcp_packet(self):
        from core.analyzer import parse_packet

        pkt = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=5555, dport=443, flags="S")
        record = parse_packet(pkt, now=1000.0)
        self.assertIsNotNone(record)
        self.assertEqual(record.protocol, Protocol.TCP)
        self.assertEqual(record.src_ip, "192.168.1.10")
        self.assertEqual(record.dst_ip, "192.168.1.20")
        self.assertEqual(record.src_port, 5555)
        self.assertEqual(record.dst_port, 443)
        self.assertIn("S", record.tcp_flags)

    def test_parses_udp_packet(self):
        from core.analyzer import parse_packet

        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1111, dport=53)
        record = parse_packet(pkt, now=1000.0)
        self.assertIsNotNone(record)
        self.assertEqual(record.protocol, Protocol.UDP)
        self.assertEqual(record.dst_port, 53)

    def test_parses_icmp_packet(self):
        from core.analyzer import parse_packet

        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
        record = parse_packet(pkt, now=1000.0)
        self.assertIsNotNone(record)
        self.assertEqual(record.protocol, Protocol.ICMP)
        self.assertIsNone(record.src_port)

    def test_non_ip_packet_returns_none(self):
        from core.analyzer import parse_packet
        from scapy.layers.l2 import Ether, ARP  # type: ignore

        pkt = Ether() / ARP()
        record = parse_packet(pkt, now=1000.0)
        self.assertIsNone(record)

    def test_malformed_packet_does_not_raise(self):
        from core.analyzer import parse_packet

        class Broken:
            def haslayer(self, _layer):
                raise RuntimeError("boom")

        # Should not raise; should return None.
        record = parse_packet(Broken(), now=1000.0)
        self.assertIsNone(record)


if __name__ == "__main__":
    unittest.main()
