"""
exporters/csv_exporter.py

Streams session events (packet summaries and threat alerts) to a CSV file
as they happen, so a crash or Ctrl+C never loses the whole session. Writes
are buffered and flushed periodically (config.export.csv_flush_every) for
a reasonable balance of durability and disk I/O.

Only packet metadata is written.
"""

from __future__ import annotations

import csv
import logging
import threading
from pathlib import Path
from typing import Optional

from core.models import PacketRecord, ThreatAlert

logger = logging.getLogger("nta.csv_exporter")

FIELDNAMES = [
    "timestamp",
    "type",  # "PACKET" or "ALERT"
    "src_ip",
    "dst_ip",
    "protocol",
    "size",
    "src_port",
    "dst_port",
    "tcp_flags",
    "ttl",
    "rule",
    "severity",
    "detail",
    "evidence_count",
    "risk_score",
]


class CsvExporter:
    def __init__(self, path: Path, flush_every: int = 25) -> None:
        self.path = Path(path)
        self.flush_every = max(1, flush_every)
        self._lock = threading.Lock()
        self._pending_since_flush = 0
        self._file = None
        self._writer: Optional[csv.DictWriter] = None
        self._open()

    def _open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        is_new = not self.path.exists() or self.path.stat().st_size == 0
        self._file = open(self.path, mode="a", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._file, fieldnames=FIELDNAMES)
        if is_new:
            self._writer.writeheader()
            self._file.flush()

    def write_packet(self, record: PacketRecord) -> None:
        row = {
            "timestamp": record.timestamp,
            "type": "PACKET",
            "src_ip": record.src_ip,
            "dst_ip": record.dst_ip,
            "protocol": record.protocol.value,
            "size": record.size,
            "src_port": record.src_port if record.src_port is not None else "",
            "dst_port": record.dst_port if record.dst_port is not None else "",
            "tcp_flags": record.tcp_flags or "",
            "ttl": record.ttl if record.ttl is not None else "",
            "rule": "",
            "severity": "",
            "detail": "",
            "evidence_count": "",
            "risk_score": "",
        }
        self._write_row(row)

    def write_alert(self, alert: ThreatAlert) -> None:
        row = {
            "timestamp": alert.timestamp,
            "type": "ALERT",
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip or "",
            "protocol": "",
            "size": "",
            "src_port": "",
            "dst_port": "",
            "tcp_flags": "",
            "ttl": "",
            "rule": alert.rule,
            "severity": alert.severity.value,
            "detail": alert.detail,
            "evidence_count": alert.evidence_count,
            "risk_score": alert.risk_score,
        }
        self._write_row(row)

    def _write_row(self, row: dict) -> None:
        with self._lock:
            if self._writer is None:
                return
            try:
                self._writer.writerow(row)
                self._pending_since_flush += 1
                if self._pending_since_flush >= self.flush_every:
                    self._file.flush()
                    self._pending_since_flush = 0
            except Exception:  # noqa: BLE001
                logger.exception("Failed to write CSV row.")

    def close(self) -> None:
        with self._lock:
            if self._file is not None:
                try:
                    self._file.flush()
                    self._file.close()
                except Exception:  # noqa: BLE001
                    logger.exception("Failed to close CSV file cleanly.")
                self._file = None
                self._writer = None

    def __enter__(self) -> "CsvExporter":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
