"""
core/capture.py

Runs Scapy's sniff() loop in its own daemon thread and pushes raw packets
onto a thread-safe queue for the analyzer thread to consume. Capture is
intentionally decoupled from parsing/rendering: if the dashboard stalls,
capture keeps running (up to the configured queue size) instead of dropping
packets on the floor immediately.

This module never inspects or logs payload contents — it only hands whole
Scapy packet objects to the queue, and it is core/analyzer.py's job to pull
out header metadata only.
"""

from __future__ import annotations

import logging
import queue
import threading
from typing import Optional

from config import CaptureConfig, is_windows, is_linux, npcap_hint, linux_permission_hint

logger = logging.getLogger("nta.capture")


class CaptureError(Exception):
    """Raised when packet capture cannot start for an actionable reason."""


class CaptureThread(threading.Thread):
    """
    Wraps scapy.sniff() in a background thread.

    Packets are placed on `packet_queue` as raw Scapy packet objects. A
    `stop_event` allows graceful shutdown; scapy's `stop_filter` callback is
    polled between packets so Ctrl+C / programmatic stop() actually ends the
    sniff loop instead of blocking forever.
    """

    def __init__(
        self,
        config: CaptureConfig,
        packet_queue: "queue.Queue",
        on_error: Optional[callable] = None,
    ) -> None:
        super().__init__(name="CaptureThread", daemon=True)
        self.config = config
        self.packet_queue = packet_queue
        self.stop_event = threading.Event()
        self.on_error = on_error
        self._packets_captured = 0
        self._start_error: Optional[str] = None

    # -- public API ---------------------------------------------------

    def stop(self) -> None:
        self.stop_event.set()

    @property
    def packets_captured(self) -> int:
        return self._packets_captured

    @property
    def start_error(self) -> Optional[str]:
        return self._start_error

    # -- thread entry point --------------------------------------------

    def run(self) -> None:
        try:
            self._run_sniff()
        except Exception as exc:  # noqa: BLE001 - we want to surface any error
            message = self._friendly_error(exc)
            self._start_error = message
            logger.error(message)
            if self.on_error:
                self.on_error(message)

    # -- internals -------------------------------------------------------

    def _run_sniff(self) -> None:
        # Imported lazily so the rest of the app (config, tests for pure
        # logic modules) can run in environments without Scapy/npcap fully
        # configured, and so a slow scapy import doesn't delay --help etc.
        try:
            from scapy.all import sniff  # type: ignore
        except ImportError as exc:  # pragma: no cover - environment issue
            raise CaptureError(
                "Scapy is not installed. Run: pip install -r requirements.txt"
            ) from exc

        def _on_packet(pkt) -> None:
            self._packets_captured += 1
            try:
                self.packet_queue.put(pkt, timeout=1.0)
            except queue.Full:
                logger.warning("Packet queue full; dropping packet to protect memory.")

        def _should_stop(_pkt) -> bool:
            if self.config.max_packets and self._packets_captured >= self.config.max_packets:
                return True
            return self.stop_event.is_set()

        sniff_kwargs = dict(
            prn=_on_packet,
            store=False,
            stop_filter=_should_stop,
        )
        if self.config.interface:
            sniff_kwargs["iface"] = self.config.interface
        if self.config.bpf_filter:
            sniff_kwargs["filter"] = self.config.bpf_filter

        sniff(**sniff_kwargs)

    def _friendly_error(self, exc: Exception) -> str:
        text = str(exc).lower()
        permission_signals = ("permission", "operation not permitted", "winerror 5", "access is denied")

        if any(sig in text for sig in permission_signals):
            if is_windows():
                return f"Permission denied while starting capture.\n{npcap_hint()}"
            if is_linux():
                return f"Permission denied while starting capture.\n{linux_permission_hint()}"
            return (
                "Permission denied while starting capture. Packet capture "
                "typically requires elevated/administrator privileges."
            )

        if "no such device" in text or "does not exist" in text or "unknown interface" in text:
            return (
                f"Network interface '{self.config.interface}' was not found. "
                "Run this tool with --list-interfaces to see available interfaces, "
                "or leave the interface unset to use the default."
            )

        if isinstance(exc, CaptureError):
            return str(exc)

        return f"Packet capture failed to start: {exc}"


def list_interfaces() -> list[str]:
    """Return a human-readable list of available network interfaces."""
    try:
        from scapy.all import get_if_list  # type: ignore
    except ImportError:
        return []
    try:
        return list(get_if_list())
    except Exception:  # noqa: BLE001
        return []
