"""
exporters/pcap_exporter.py

Writes captured packets to a standard PCAP file that can be opened in
Wireshark for deeper offline analysis. This is the one place in the
codebase that deliberately handles full raw packets (not just metadata),
because a PCAP file is only useful if Wireshark can parse real frames from
it. The rest of the analyzer/dashboard/CSV pipeline never touches this raw
data — they only see the metadata-only PacketRecord objects.

Uses Scapy's PcapWriter for incremental, append-as-you-go writes so a long
session doesn't have to hold every packet in memory.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Optional

logger = logging.getLogger("nta.pcap_exporter")


class PcapExporter:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._writer = None
        self._count = 0
        self._open()

    def _open(self) -> None:
        try:
            from scapy.utils import PcapWriter  # type: ignore
        except ImportError:
            logger.warning("Scapy not available; PCAP export disabled.")
            self._writer = None
            return

        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._writer = PcapWriter(str(self.path), append=True, sync=True)
        except Exception:  # noqa: BLE001
            logger.exception("Failed to open PCAP writer at %s", self.path)
            self._writer = None

    def write(self, pkt) -> None:
        """Write one raw Scapy packet to the PCAP file, if export is active."""
        with self._lock:
            if self._writer is None:
                return
            try:
                self._writer.write(pkt)
                self._count += 1
            except Exception:  # noqa: BLE001
                logger.exception("Failed to write packet to PCAP.")

    @property
    def packet_count(self) -> int:
        return self._count

    @property
    def enabled(self) -> bool:
        return self._writer is not None

    def close(self) -> None:
        with self._lock:
            if self._writer is not None:
                try:
                    self._writer.close()
                except Exception:  # noqa: BLE001
                    logger.exception("Failed to close PCAP writer cleanly.")
                self._writer = None

    def __enter__(self) -> "PcapExporter":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
