"""
Detection module for network threat detection.

Exports all detector classes and the detection engine.
"""

from detection.base import BaseDetector
from detection.dns_anomaly import DnsAnomalyDetector
from detection.engine import DetectionEngine
from detection.icmp_sweep import IcmpSweepDetector
from detection.port_scan import PortScanDetector
from detection.syn_flood import SynFloodDetector
from detection.syn_scan import SynScanDetector
from detection.traffic_spike import TrafficSpikeDetector
from detection.unusual_port import UnusualPortDetector

__all__ = [
    "BaseDetector",
    "DetectionEngine",
    "SynScanDetector",
    "PortScanDetector",
    "IcmpSweepDetector",
    "SynFloodDetector",
    "TrafficSpikeDetector",
    "DnsAnomalyDetector",
    "UnusualPortDetector",
]