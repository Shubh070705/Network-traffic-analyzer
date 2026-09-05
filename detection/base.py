from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from core.models import PacketRecord, ThreatAlert


class BaseDetector(ABC):
    """Shared interface for packet-level detection rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique rule identifier (e.g. 'NET-001')."""
        pass

    @property
    @abstractmethod
    def rule_name(self) -> str:
        """Human-readable name of the detection rule."""
        pass

    @abstractmethod
    def observe(self, record: PacketRecord) -> Optional[ThreatAlert]:
        """Inspect one packet record and optionally return a ThreatAlert."""
        pass

    def reset(self) -> None:
        """Reset all internal state held by this detector."""
        pass

    def cleanup_state(self, now: float) -> None:
        """Purge expired state entries during long runs."""
        pass
