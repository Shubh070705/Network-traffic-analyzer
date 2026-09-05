"""
config.py

Central configuration for Network Analyzer - Real-Time Network Traffic Analyzer & Behavioral NIDS.

All tunable values live here so the rest of the codebase never hard-codes
thresholds, paths, or platform-specific assumptions. Values can be overridden
with environment variables, which is convenient for CI/tests and for users
who don't want to edit source to change a threshold.

SECURITY NOTE:
This tool is intended ONLY for monitoring a computer or network you own or
are explicitly authorized to test. It inspects packet METADATA only
(addresses, ports, protocol, size, timing). It never reads, stores, or
displays payload contents, and therefore never captures passwords or other
credentials. Detection rules below are heuristics, not proof of attack —
they can and will produce false positives on legitimate bursty traffic
(e.g., a browser opening many connections at once).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------- #
# Project identity
# --------------------------------------------------------------------------- #

APP_NAME = "NETWORK ANALYZER"
APP_VERSION = "1.0.0"
APP_TAGLINE = "Real-Time Network Traffic Analyzer & Behavioral NIDS"
APP_AUTHOR = "by Shubh070705"


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_str(name: str, default: str) -> str:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw


# ---------------------------------------------------------------------------
# Project paths
# ---------------------------------------------------------------------------

PROJECT_ROOT: Path = Path(__file__).resolve().parent
LOGS_DIR: Path = PROJECT_ROOT / "logs"
CAPTURES_DIR: Path = PROJECT_ROOT / "captures"

# Ensure output directories always exist, regardless of where the tool is
# invoked from. This prevents "file not found" errors on first run.
LOGS_DIR.mkdir(parents=True, exist_ok=True)
CAPTURES_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class DetectionConfig:
    """Thresholds for the heuristic threat-detection engine."""

    # SYN-scan detection: N or more distinct destination ports contacted
    # with lone SYN packets (no completed handshake) from one source within
    # the sliding window is flagged.
    syn_scan_port_threshold: int = field(
        default_factory=lambda: _env_int("NTA_SYN_SCAN_PORT_THRESHOLD", 15)
    )
    syn_scan_window_seconds: float = field(
        default_factory=lambda: _env_float("NTA_SYN_SCAN_WINDOW_SECONDS", 5.0)
    )

    # Port-scan detection: N or more distinct destination ports contacted
    # (any protocol/flags) on a single destination host from one source
    # within the sliding window is flagged.
    port_scan_port_threshold: int = field(
        default_factory=lambda: _env_int("NTA_PORT_SCAN_PORT_THRESHOLD", 20)
    )
    port_scan_window_seconds: float = field(
        default_factory=lambda: _env_float("NTA_PORT_SCAN_WINDOW_SECONDS", 10.0)
    )

    # Severity escalation multipliers applied to the base threshold.
    medium_multiplier: float = field(
        default_factory=lambda: _env_float("NTA_MEDIUM_MULTIPLIER", 1.5)
    )
    high_multiplier: float = field(
        default_factory=lambda: _env_float("NTA_HIGH_MULTIPLIER", 2.5)
    )

    # How long an IP stays on the threat watchlist after its last alert.
    watchlist_ttl_seconds: float = field(
        default_factory=lambda: _env_float("NTA_WATCHLIST_TTL_SECONDS", 300.0)
    )

    # ICMP sweep detection: N or more unique destination hosts contacted via
    # ICMP within the sliding window is flagged.
    icmp_sweep_host_threshold: int = field(
        default_factory=lambda: _env_int("NTA_ICMP_SWEEP_HOST_THRESHOLD", 10)
    )
    icmp_sweep_window_seconds: float = field(
        default_factory=lambda: _env_float("NTA_ICMP_SWEEP_WINDOW_SECONDS", 30.0)
    )

    # SYN flood detection: N or more SYN packets within the sliding window.
    syn_flood_packet_threshold: int = field(
        default_factory=lambda: _env_int("NTA_SYN_FLOOD_PACKET_THRESHOLD", 100)
    )
    syn_flood_window_seconds: float = field(
        default_factory=lambda: _env_float("NTA_SYN_FLOOD_WINDOW_SECONDS", 10.0)
    )

    # Traffic spike detection: alert when PPS exceeds baseline by this multiplier.
    traffic_spike_multiplier: float = field(
        default_factory=lambda: _env_float("NTA_TRAFFIC_SPIKE_MULTIPLIER", 5.0)
    )
    traffic_spike_window_seconds: float = field(
        default_factory=lambda: _env_float("NTA_TRAFFIC_SPIKE_WINDOW_SECONDS", 10.0)
    )

    # DNS anomaly detection: N or more DNS requests from one source within window.
    dns_anomaly_request_threshold: int = field(
        default_factory=lambda: _env_int("NTA_DNS_ANOMALY_REQUEST_THRESHOLD", 50)
    )
    dns_anomaly_window_seconds: float = field(
        default_factory=lambda: _env_float("NTA_DNS_ANOMALY_WINDOW_SECONDS", 10.0)
    )

    # Unusual port detection: N or more uncommon ports contacted on a single host.
    unusual_port_threshold: int = field(
        default_factory=lambda: _env_int("NTA_UNUSUAL_PORT_THRESHOLD", 5)
    )
    unusual_port_window_seconds: float = field(
        default_factory=lambda: _env_float("NTA_UNUSUAL_PORT_WINDOW_SECONDS", 60.0)
    )


@dataclass
class CaptureConfig:
    """Settings controlling how packets are captured."""

    # None means "let the user choose interactively / use Scapy default".
    interface: str | None = field(
        default_factory=lambda: os.environ.get("NTA_INTERFACE") or None
    )

    # Berkeley Packet Filter applied at capture time. Empty string = no
    # filter (capture everything). Keeping this configurable lets users
    # scope the tool to specific hosts/ports on shared networks.
    bpf_filter: str = field(default_factory=lambda: _env_str("NTA_BPF_FILTER", ""))

    # Max number of packets to keep queued between the capture thread and
    # the analyzer thread before capture starts blocking (backpressure).
    queue_max_size: int = field(default_factory=lambda: _env_int("NTA_QUEUE_MAX_SIZE", 20000))

    # Optional hard cap on total packets captured this session (0 = unlimited).
    max_packets: int = field(default_factory=lambda: _env_int("NTA_MAX_PACKETS", 0))


@dataclass
class DashboardConfig:
    """Settings controlling the Rich live dashboard."""

    refresh_per_second: float = field(
        default_factory=lambda: _env_float("NTA_REFRESH_FPS", 4.0)
    )
    mask_ips: bool = field(default_factory=lambda: _env_bool("NTA_MASK_IPS", False))
    top_n_hosts: int = field(default_factory=lambda: _env_int("NTA_TOP_N_HOSTS", 8))
    live_stream_rows: int = field(default_factory=lambda: _env_int("NTA_LIVE_STREAM_ROWS", 12))
    watchlist_rows: int = field(default_factory=lambda: _env_int("NTA_WATCHLIST_ROWS", 8))


@dataclass
class ExportConfig:
    """Settings controlling CSV and PCAP export."""

    csv_path: Path = field(
        default_factory=lambda: Path(_env_str("NTA_CSV_PATH", str(LOGS_DIR / "session_events.csv")))
    )
    pcap_path: Path = field(
        default_factory=lambda: Path(_env_str("NTA_PCAP_PATH", str(CAPTURES_DIR / "session_capture.pcap")))
    )
    # Flush CSV rows to disk every N events, so a crash doesn't lose the
    # whole session.
    csv_flush_every: int = field(default_factory=lambda: _env_int("NTA_CSV_FLUSH_EVERY", 25))


@dataclass
class AppConfig:
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    export: ExportConfig = field(default_factory=ExportConfig)

    # Statistics engine: size of the rolling window (seconds) used to
    # compute packets/sec and bytes/sec.
    stats_window_seconds: float = field(
        default_factory=lambda: _env_float("NTA_STATS_WINDOW_SECONDS", 5.0)
    )


def get_config() -> AppConfig:
    """Build a fresh AppConfig from current environment variables/defaults."""
    return AppConfig()


def is_windows() -> bool:
    return sys.platform.startswith("win")


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def npcap_hint() -> str:
    return (
        "Windows packet capture requires Npcap installed in "
        "'WinPcap API-compatible mode'. Download it from https://npcap.com/#download, "
        "run the installer as Administrator, and check the "
        "'Install Npcap in WinPcap API-compatible Mode' box. Then run this "
        "program from an elevated (Administrator) terminal."
    )


def linux_permission_hint() -> str:
    return (
        "Linux packet capture requires raw socket privileges. Either run "
        "with sudo (e.g. 'sudo python3 main.py'), or grant the capability "
        "to your Python interpreter once with: "
        "'sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))'"
    )
