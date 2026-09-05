#!/usr/bin/env python3
"""
main.py

Entry point for NETWORK ANALYZER.

Wires together: CaptureThread -> thread-safe Queue -> AnalyzerThread
(parsing + statistics + detection) -> Rich Dashboard, with CSV and PCAP
exporters running as sinks alongside the dashboard.

USAGE
    python main.py                      # use default/auto interface
    python main.py --interface eth0     # capture on a specific interface
    python main.py --list-interfaces    # show available interfaces and exit
    python main.py --mask-ips           # pseudonymize IPs on screen
    python main.py --bpf "tcp or udp"   # apply a capture filter
    python main.py --no-pcap            # disable PCAP export
    python main.py --no-csv             # disable CSV export

SECURITY
    Only run this against a computer/network you own or are authorized to
    monitor. It reads packet metadata only (addresses, ports, protocol,
    size, timing, TTL) and never inspects or stores payload contents or
    credentials. Detection alerts are heuristic and can false-positive.
"""

from __future__ import annotations

import argparse
import logging
import platform
import queue
import sys
import time as time_module
from dataclasses import replace

from config import get_config, is_windows, is_linux, npcap_hint, linux_permission_hint
from core.capture import CaptureThread, CaptureError, list_interfaces
from core.analyzer import AnalyzerThread
from core.statistics import StatisticsEngine
from detection.engine import DetectionEngine
from dashboard.keyboard import KeyboardController
from dashboard.ui import Dashboard
from exporters.csv_exporter import CsvExporter
from exporters.pcap_exporter import PcapExporter

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("nta.main")


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="NETWORK ANALYZER",
        description="Real-time packet capture, traffic statistics, and heuristic threat detection.",
    )
    parser.add_argument("--interface", "-i", default=None, help="Network interface to capture on.")
    parser.add_argument(
        "--list-interfaces", action="store_true", help="List available network interfaces and exit."
    )
    parser.add_argument("--bpf", default=None, help="BPF capture filter, e.g. 'tcp or udp'.")
    parser.add_argument("--mask-ips", action="store_true", help="Pseudonymize IP addresses on screen.")
    parser.add_argument("--no-pcap", action="store_true", help="Disable PCAP export.")
    parser.add_argument("--no-csv", action="store_true", help="Disable CSV export.")
    parser.add_argument(
        "--max-packets", type=int, default=None, help="Stop automatically after N packets (0/unset = unlimited)."
    )
    parser.add_argument(
        "--syn-scan-threshold", type=int, default=None, help="Distinct ports to trigger a SYN-scan alert."
    )
    parser.add_argument(
        "--port-scan-threshold", type=int, default=None, help="Distinct ports to trigger a port-scan alert."
    )
    return parser.parse_args(argv)


def build_config(args: argparse.Namespace):
    config = get_config()

    if args.interface:
        config.capture.interface = args.interface
    if args.bpf is not None:
        config.capture.bpf_filter = args.bpf
    if args.max_packets is not None:
        config.capture.max_packets = args.max_packets
    if args.mask_ips:
        config.dashboard.mask_ips = True
    if args.syn_scan_threshold is not None:
        config.detection = replace(config.detection, syn_scan_port_threshold=args.syn_scan_threshold)
    if args.port_scan_threshold is not None:
        config.detection = replace(config.detection, port_scan_port_threshold=args.port_scan_threshold)

    return config


def print_permission_help() -> None:
    if is_windows():
        print(npcap_hint())
    elif is_linux():
        print(linux_permission_hint())
    else:
        print("Packet capture typically requires elevated/administrator privileges on this OS.")


def run() -> int:
    args = parse_args()

    if args.list_interfaces:
        interfaces = list_interfaces()
        if not interfaces:
            print("No interfaces found, or Scapy could not enumerate them.")
            print("Make sure dependencies are installed: pip install -r requirements.txt")
            if is_windows():
                print(npcap_hint())
            return 1
        print("Available interfaces:")
        for name in interfaces:
            print(f"  - {name}")
        return 0

    config = build_config(args)

    packet_queue: "queue.Queue" = queue.Queue(maxsize=config.capture.queue_max_size)
    statistics = StatisticsEngine(window_seconds=config.stats_window_seconds)

    csv_exporter = None
    if not args.no_csv:
        try:
            csv_exporter = CsvExporter(config.export.csv_path, flush_every=config.export.csv_flush_every)
        except OSError as exc:
            print(f"Warning: could not open CSV export file ({exc}). Continuing without CSV export.")
            csv_exporter = None

    pcap_exporter = None
    if not args.no_pcap:
        try:
            pcap_exporter = PcapExporter(config.export.pcap_path)
            if not pcap_exporter.enabled:
                print("Warning: PCAP export unavailable (Scapy missing or file error). Continuing without it.")
                pcap_exporter = None
        except OSError as exc:
            print(f"Warning: could not open PCAP export file ({exc}). Continuing without PCAP export.")
            pcap_exporter = None

    def on_alert(alert):
        if csv_exporter:
            csv_exporter.write_alert(alert)

    detection = DetectionEngine(config.detection, on_alert=on_alert)

    def on_record(record):
        if csv_exporter:
            csv_exporter.write_packet(record)

    def on_raw_packet(pkt):
        if pcap_exporter:
            pcap_exporter.write(pkt)

    analyzer = AnalyzerThread(
        packet_queue=packet_queue,
        statistics=statistics,
        detection=detection,
        live_stream_maxlen=max(200, config.dashboard.live_stream_rows * 5),
        on_record=on_record,
        on_raw_packet=on_raw_packet,
    )

    capture_error_holder = {"message": None}

    def on_capture_error(message: str) -> None:
        capture_error_holder["message"] = message

    capture = CaptureThread(config.capture, packet_queue, on_error=on_capture_error)

    # Get interface name for dashboard display
    interface_name = config.capture.interface or "auto-detect"

    # Get OS info for dashboard display
    os_info = f"{platform.system()} {platform.release()}"

    # Record start time for uptime display
    start_time = time_module.time()

    dashboard = Dashboard(
        config.dashboard,
        interface_name=interface_name,
        os_info=os_info,
        start_time=start_time,
    )
    keyboard = KeyboardController(dashboard.filter_state)

    analyzer.start()
    capture.start()

    # Give the capture thread a brief moment to fail fast on permission
    # errors before we take over the terminal with the Live dashboard.
    time_module.sleep(0.5)
    if capture_error_holder["message"]:
        print("Failed to start packet capture:\n")
        print(capture_error_holder["message"])
        analyzer.stop()
        if csv_exporter:
            csv_exporter.close()
        if pcap_exporter:
            pcap_exporter.close()
        return 1

    exit_code = 0
    try:
        keyboard.start()
        with dashboard.make_live() as live:
            while True:
                if dashboard.filter_state.quit_requested:
                    dashboard.status_message = "Stopping"
                    dashboard.status_style = "yellow"
                    break

                if capture_error_holder["message"]:
                    dashboard.status_message = "Capture error"
                    dashboard.status_style = "bold red"

                stats = statistics.snapshot()
                live_records = analyzer.snapshot_live_stream()
                watchlist = detection.watchlist_snapshot()
                alerts = detection.recent_alerts()
                incidents = detection.incidents_snapshot()

                footer_extra = f"packets queued: {packet_queue.qsize()}"
                if pcap_exporter and pcap_exporter.enabled:
                    footer_extra += f"  |  pcap: {pcap_exporter.packet_count}"

                live.update(
                    dashboard.render(
                        stats=stats,
                        live_records=live_records,
                        watchlist=watchlist,
                        alerts=alerts,
                        incidents=incidents,
                        footer_extra=footer_extra,
                    )
                )

                if not capture.is_alive() and packet_queue.empty() and config.capture.max_packets:
                    # Finite capture session completed.
                    dashboard.status_message = "Capture complete"
                    dashboard.status_style = "green"
                    live.update(
                        dashboard.render(stats, live_records, watchlist, alerts, incidents, footer_extra)
                    )
                    time_module.sleep(1.5)
                    break

                time_module.sleep(1.0 / max(config.dashboard.refresh_per_second, 1.0))
    except KeyboardInterrupt:
        pass
    except Exception:  # noqa: BLE001
        logger.exception("Unexpected error in dashboard loop.")
        exit_code = 1
    finally:
        keyboard.stop()
        capture.stop()
        analyzer.stop()
        capture.join(timeout=2.0)
        analyzer.join(timeout=2.0)
        if csv_exporter:
            csv_exporter.close()
        if pcap_exporter:
            pcap_exporter.close()

        print("\nSession stopped.")
        print(f"Packets processed: {analyzer.processed_count} (malformed/skipped: {analyzer.malformed_count})")
        if csv_exporter is not None or not args.no_csv:
            print(f"CSV log: {config.export.csv_path}")
        if pcap_exporter is not None or not args.no_pcap:
            print(f"PCAP file: {config.export.pcap_path}")

    return exit_code


def main() -> None:
    try:
        sys.exit(run())
    except CaptureError as exc:
        print(f"Capture error: {exc}")
        print_permission_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
