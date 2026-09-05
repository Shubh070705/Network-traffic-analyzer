"""Color, badge, and formatting helpers for the Rich dashboard."""

from __future__ import annotations

from rich.text import Text

# --------------------------------------------------------------------------- #
# Header colors
# --------------------------------------------------------------------------- #

HEADER_BG = "dark_blue"

# --------------------------------------------------------------------------- #
# Severity Colors
# --------------------------------------------------------------------------- #
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold orange3",
    "MEDIUM": "bold yellow",
    "LOW": "cyan",
}

# --------------------------------------------------------------------------- #
# Protocol Colors
# --------------------------------------------------------------------------- #

PROTOCOL_COLORS = {
    "TCP": "cyan",
    "UDP": "magenta",
    "ICMP": "green",
    "OTHER": "grey62",
}

# --------------------------------------------------------------------------- #
# Status Colors
# --------------------------------------------------------------------------- #

STATUS_LIVE = "bold green"
BORDER_HEADER = "cyan"
BORDER_KPI = "blue"
BORDER_TRAFFIC = "cyan"
BORDER_THREATS = "red"
BORDER_STREAM = "white"
BORDER_FOOTER = "grey35"

# --------------------------------------------------------------------------- #
# Badge helpers
# --------------------------------------------------------------------------- #


def severity_badge(severity: str, text: str | None = None) -> Text:
    """Create a styled severity label."""
    severity = severity.upper()
    style = SEVERITY_COLORS.get(severity, "white")
    badge_text = text if text is not None else severity
    return Text(f"[{badge_text}]", style=style)


def protocol_badge(protocol: str) -> Text:
    """Create a styled protocol label."""
    style = PROTOCOL_COLORS.get(protocol.upper(), "white")
    return Text(protocol.upper(), style=style)


# --------------------------------------------------------------------------- #
# Symbols for Rich display
# --------------------------------------------------------------------------- #

SYMBOL_ARROW = "→"
SYMBOL_SHIELD = "🛡"
SYMBOL_NETWORK = "◈"
SYMBOL_PACKET = "▣"

# --------------------------------------------------------------------------- #
# Formatting Helpers
# --------------------------------------------------------------------------- #


def format_bytes(bytes_count: int) -> str:
    """Format byte count with appropriate unit (KB, MB, GB)."""
    if bytes_count < 1024:
        return f"{bytes_count} B"
    elif bytes_count < 1024 * 1024:
        return f"{bytes_count / 1024:.1f} KB"
    elif bytes_count < 1024 * 1024 * 1024:
        return f"{bytes_count / (1024 * 1024):.1f} MB"
    else:
        return f"{bytes_count / (1024 * 1024 * 1024):.1f} GB"


def format_number(num: int) -> str:
    """Format large numbers with commas."""
    return f"{num:,}"


def format_rate(rate: float, suffix: str = "/s") -> str:
    """Format a rate value with appropriate precision."""
    if rate < 10:
        return f"{rate:.2f}{suffix}"
    elif rate < 1000:
        return f"{rate:.1f}{suffix}"
    else:
        return f"{rate:,.0f}{suffix}"
