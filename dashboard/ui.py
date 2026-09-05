"""
dashboard/ui.py

Renders the live Rich dashboard for Network Analyzer. Rendering only reads
snapshots handed to it and never touches the capture/analyzer threads directly.
"""

from __future__ import annotations

import hashlib
import platform
from datetime import datetime
from typing import List, Optional

from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from config import APP_AUTHOR, APP_NAME, APP_TAGLINE, APP_VERSION, DashboardConfig
from core.models import PacketRecord, Severity, StatsSnapshot, ThreatAlert, WatchlistEntry
from dashboard.filtering import (
    ALL,
    DashboardFilterState,
    FilterMode,
    build_host_activity,
    filter_alerts,
    filter_host_activity,
    filter_incidents,
    filter_records,
    filter_watchlist,
)
from dashboard.theme import (
    BORDER_FOOTER,
    BORDER_HEADER,
    BORDER_KPI,
    BORDER_STREAM,
    BORDER_THREATS,
    BORDER_TRAFFIC,
    HEADER_BG,
    PROTOCOL_COLORS,
    STATUS_LIVE,
    SYMBOL_ARROW,
    SYMBOL_NETWORK,
    SYMBOL_PACKET,
    SYMBOL_SHIELD,
    format_bytes,
    format_number,
    format_rate,
    protocol_badge,
    severity_badge,
)
from incident import Incident


def mask_ip(ip: str) -> str:
    """
    Produce a stable, non-reversible pseudonym for an IP address.

    The same input maps to the same masked output within a process run, which
    keeps traffic patterns such as top talkers legible in demos.
    """
    digest = hashlib.sha256(ip.encode("utf-8")).hexdigest()[:8]
    return f"host-{digest}"


class Dashboard:
    def __init__(
        self,
        config: DashboardConfig,
        console: Optional[Console] = None,
        interface_name: str = "auto",
        os_info: str = "",
        start_time: Optional[float] = None,
    ) -> None:
        self.config = config
        self.console = console or Console()
        self.layout = self._build_layout()
        self.started_at = datetime.now() if start_time is None else datetime.fromtimestamp(start_time)
        self.start_time_ts = start_time if start_time is not None else datetime.now().timestamp()
        self.status_message = "LIVE"
        self.status_style = STATUS_LIVE
        self.interface_name = interface_name
        self.os_info = os_info or f"{platform.system()} {platform.release()}"
        self.filter_state = DashboardFilterState()

    # -- layout ------------------------------------------------------------

    def _build_layout(self) -> Layout:
        """Build the dashboard layout."""
        layout = Layout(name="root")
        layout.split(
            Layout(name="header", size=5),
            Layout(name="kpi_banner", size=3),
            Layout(name="body"),
            Layout(name="footer", size=2),
        )
        # Add the stream below the summary panels.
        layout["body"].split(
            Layout(name="panels", ratio=1),
            Layout(name="stream", ratio=1),
        )
        layout["panels"].split_row(
            Layout(name="left", ratio=1),
            Layout(name="right", ratio=1),
        )
        layout["left"].split(
            Layout(name="search", size=3),
            Layout(name="filter", size=8),
            Layout(name="traffic", ratio=1),
        )
        layout["right"].split(
            Layout(name="threats", ratio=1),
        )
        return layout

    def _display_ip(self, ip: str) -> str:
        return mask_ip(ip) if self.config.mask_ips else ip

    def _uptime_str(self) -> str:
        """Format dashboard uptime."""
        delta = datetime.now() - self.started_at
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours > 0:
            return f"{hours:d}:{minutes:02d}:{seconds:02d}"
        else:
            return f"{minutes:d}:{seconds:02d}"

    # -- panel builders ------------------------------------------------

    def _header_panel(self) -> Panel:
        """Build the dashboard header."""
        title = Text()
        title.append(f" {SYMBOL_SHIELD} ", style="cyan")
        title.append(APP_NAME, style="bold white")
        title.append(f" v{APP_VERSION}", style="cyan dim")
        title.append(f"  {SYMBOL_ARROW}  ", style="grey50")
        title.append(APP_AUTHOR, style="grey70")

        tagline = Text(APP_TAGLINE, style="grey70 italic")

        subtitle = Text()
        subtitle.append("  Status: ", style="grey70")
        subtitle.append(self.status_message, style=self.status_style)
        subtitle.append("  |  ", style="grey35")
        subtitle.append(f"Interface: ", style="grey70")
        subtitle.append(self.interface_name, style="cyan")
        subtitle.append("  |  ", style="grey35")
        subtitle.append(f"OS: ", style="grey70")
        subtitle.append(self.os_info, style="white")
        subtitle.append("  |  ", style="grey35")
        subtitle.append(f"Uptime: ", style="grey70")
        subtitle.append(self._uptime_str(), style="green")
        subtitle.append("  |  ", style="grey35")
        subtitle.append("FILTER: ", style="grey70")
        subtitle.append(self.filter_state.mode.value, style="bold cyan")

        group = Group(
            Align.center(title),
            Align.center(tagline),
            Align.center(subtitle),
        )
        return Panel(group, border_style=BORDER_HEADER, style=f"on {HEADER_BG}" if HEADER_BG else None)

    def _filter_panel(self) -> Panel:
        """Build the compact active filter panel."""
        table = Table.grid(padding=(0, 1), expand=True)
        table.add_column(style="grey70", width=10)
        table.add_column(style="bold white", overflow="fold")

        table.add_row("Protocol:", self.filter_state.protocol)
        table.add_row("Severity:", self.filter_state.severity)
        table.add_row("Host:", self.filter_state.host)
        table.add_row("Rule:", self.filter_state.rule)
        table.add_row("Mode:", self.filter_state.mode.value)

        shortcuts = Text()
        shortcuts.append("[1]ALL ", style="grey50")
        shortcuts.append("[2]THREATS ", style="grey50")
        shortcuts.append("[3]TCP ", style="grey50")
        shortcuts.append("[4]UDP ", style="grey50")
        shortcuts.append("[5]HOSTS ", style="grey50")
        shortcuts.append("[/]SEARCH ", style="grey50")
        shortcuts.append("[ESC]CLEAR ", style="grey50")
        shortcuts.append("[Q]QUIT", style="grey50")

        return Panel(Group(table, shortcuts), title="FILTER", border_style=BORDER_TRAFFIC)

    def _search_panel(self) -> Panel:
        """Build the dashboard search bar."""
        table = Table.grid(expand=True)
        table.add_column(ratio=1)
        table.add_column(width=10, justify="right")

        search_text = self.filter_state.search if self.filter_state.has_search else ALL
        label_style = "bold yellow" if self.filter_state.search_active else "bold cyan"
        value_style = "bold white" if self.filter_state.has_search else "grey70"
        clear_style = "bold green" if self.filter_state.has_search else "grey50"

        row = Text()
        row.append("SEARCH", style=label_style)
        row.append(": ", style="grey70")
        row.append(search_text, style=value_style)
        if self.filter_state.search_active:
            row.append(" ", style="grey70")
            row.append("_", style="bold yellow")
            row.append("  INPUT ACTIVE", style="bold yellow")

        table.add_row(row, Text("[CLEAR]", style=clear_style))
        border_style = "yellow" if self.filter_state.search_active else BORDER_TRAFFIC
        return Panel(table, border_style=border_style)

    def _kpi_banner(self, stats: StatsSnapshot, threat_count: int, watchlist_count: int) -> Panel:
        """Build the KPI metrics banner."""
        table = Table.grid(padding=(0, 3), expand=True)
        table.add_column(justify="center")

        kpis = []

        kpis.append(
            Text.assemble(
                ("PACKETS ", "grey70"),
                (format_number(stats.total_packets), "bold cyan"),
            )
        )

        kpis.append(
            Text.assemble(
                ("BANDWIDTH ", "grey70"),
                (format_rate(stats.bytes_per_second, " B/s"), "bold magenta"),
            )
        )

        kpis.append(
            Text.assemble(
                ("PPS ", "grey70"),
                (format_rate(stats.packets_per_second, ""), "bold green"),
            )
        )

        threat_style = "bold red" if threat_count > 0 else "bold green"
        kpis.append(
            Text.assemble(
                ("THREATS ", "grey70"),
                (str(threat_count), threat_style),
            )
        )

        watchlist_style = "bold yellow" if watchlist_count > 0 else "grey50"
        kpis.append(
            Text.assemble(
                ("WATCHLIST ", "grey70"),
                (str(watchlist_count), watchlist_style),
            )
        )

        content = Text("  ").join(kpis)

        return Panel(
            Align.center(content),
            border_style=BORDER_KPI,
        )

    def _traffic_panel(self, stats: StatsSnapshot) -> Panel:
        """Build the traffic and protocol summary panel."""
        proto_table = Table.grid(padding=(0, 2))
        proto_table.add_column(style="grey70", width=6)
        proto_table.add_column(ratio=1)

        for proto in ("TCP", "UDP", "ICMP", "OTHER"):
            pct = stats.protocol_ratios.get(proto, 0.0)
            count = stats.protocol_counts.get(proto, 0)
            style = PROTOCOL_COLORS.get(proto, "white")

            # Build progress bar manually for better control
            bar_width = 16
            filled = int(pct / 100 * bar_width)
            bar = Text()
            bar.append("█" * filled, style=style)
            bar.append("░" * (bar_width - filled), style="grey35")

            row = Text()
            row.append(proto, style=style)
            row.append(" ")
            row.append(bar)
            row.append(f"  {pct:5.1f}% ", style="grey70")
            row.append(f"({format_number(count)})", style="grey50")

            proto_table.add_row(row)

        # Top Talkers table
        talkers_table = Table.grid(padding=(0, 1))
        talkers_table.add_column(style="grey70")
        talkers_table.add_column(justify="right", style="cyan")

        talkers_title = Text("Top Talkers", style="bold grey70")

        if stats.top_talkers:
            for ip, byte_count in stats.top_talkers[:5]:
                talkers_table.add_row(
                    self._display_ip(ip),
                    format_bytes(byte_count),
                )
        else:
            talkers_table.add_row("waiting for data...", "", style="grey50")

        group = Group(
            Text("Protocol Distribution", style="bold grey70"),
            proto_table,
            Text(""),
            talkers_title,
            talkers_table,
        )
        return Panel(group, title=f"{SYMBOL_NETWORK} Traffic & Protocols", border_style=BORDER_TRAFFIC)

    def _host_activity_panel(
        self,
        stats: StatsSnapshot,
        watchlist: List[WatchlistEntry],
        alerts: List[ThreatAlert],
    ) -> Panel:
        """Build the host-focused activity/risk view."""
        table = Table.grid(padding=(0, 1), expand=True)
        table.add_column(ratio=1)
        table.add_column(justify="right", width=12)
        table.add_column(justify="right", width=9)
        table.add_column(justify="right", width=9)

        rows = build_host_activity(stats.top_hosts, watchlist, alerts)
        rows = filter_host_activity(rows, self.filter_state)

        for row in rows[: self.config.top_n_hosts]:
            table.add_row(
                Text(self._display_ip(row.ip), style="white"),
                Text(f"Risk {row.risk_score}/100", style="bold yellow" if row.risk_score >= 60 else "yellow"),
                Text(f"Alerts {row.alert_count}", style="grey70"),
                Text(f"Pkts {row.packets}", style="cyan"),
            )

        if not rows:
            table.add_row(
                Text("waiting for host activity...", style="grey50"),
                Text(""),
                Text(""),
                Text(""),
            )

        return Panel(table, title=f"{SYMBOL_NETWORK} Host Activity", border_style=BORDER_TRAFFIC)

    def _threats_panel(
        self,
        watchlist: List[WatchlistEntry],
        alerts: List[ThreatAlert],
        incidents: List[Incident],
    ) -> Panel:
        """
        Build the incident watchlist & threat alerts panel showing:
        - Watchlist with severity badges and risk scores
        - Recent threat alerts with severity, risk score, rule name, source/target IP
        """
        # Watchlist table
        wl_table = Table.grid(padding=(0, 1), expand=True)
        wl_table.add_column(width=10)  # Severity badge
        wl_table.add_column(ratio=1)   # IP
        wl_table.add_column(justify="right", width=10)  # Risk score
        wl_table.add_column(justify="right", width=7)   # Alert count

        if watchlist:
            for entry in watchlist[:self.config.watchlist_rows]:
                severity_badge_text = severity_badge(entry.highest_severity.value)
                risk_text = Text(f"Risk {entry.highest_risk_score}/100", style="bold yellow" if entry.highest_risk_score >= 60 else "yellow")
                wl_table.add_row(
                    severity_badge_text,
                    Text(self._display_ip(entry.ip), style="white"),
                    risk_text,
                    Text(str(entry.alert_count), style="grey70"),
                )
        else:
            wl_table.add_row(
                Text("[CLEAR]", style="green"),
                Text("No active threats", style="grey50"),
                Text("", style="grey50"),
                Text("", style="grey50"),
            )

        # Recent alerts
        alert_lines = []
        for alert in reversed(alerts[-8:]):
            ts = datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")
            src = self._display_ip(alert.src_ip)
            dst = self._display_ip(alert.dst_ip) if alert.dst_ip else "N/A"

            # Format: [TIME] SEVERITY RULE Risk:X/100: src -> dst
            risk_score = getattr(alert, 'risk_score', 0)
            line = Text()
            line.append(f"[{ts}] ", style="grey50")
            line.append(severity_badge(alert.severity.value))
            line.append(f" {alert.rule}", style="white")
            line.append(f" Risk:{risk_score}/100", style="bold yellow" if risk_score >= 60 else "yellow")
            line.append(f" {SYMBOL_ARROW} ", style="grey35")
            line.append(src, style="cyan")
            line.append(f" {SYMBOL_ARROW} ", style="grey35")
            line.append(dst, style="magenta")
            alert_lines.append(line)

        if not alert_lines:
            alert_lines = [Text("  No recent alerts", style="grey50")]

        incident_lines = []
        for incident in incidents[:4]:
            rules = ",".join(sorted(incident.rules)) or "-"
            target = self._display_ip(incident.dst_ip) if incident.dst_ip else "multiple"
            line = Text()
            line.append(f"{incident.incident_id} ", style="bold white")
            line.append(severity_badge(incident.severity.value))
            line.append(f" Risk:{incident.risk_score}/100", style="yellow")
            line.append(f" {self._display_ip(incident.src_ip)} {SYMBOL_ARROW} {target}", style="grey70")
            line.append(f" rules:{rules}", style="grey50")
            incident_lines.append(line)

        if not incident_lines:
            incident_lines = [Text("  No correlated incidents", style="grey50")]

        group = Group(
            Text("Incident Watchlist", style="bold grey70"),
            wl_table,
            Text(""),
            Text("Correlated Incidents", style="bold grey70"),
            *incident_lines,
            Text(""),
            Text("Recent Threat Alerts", style="bold grey70"),
            *alert_lines,
        )
        return Panel(group, title="Threat Detection", border_style=BORDER_THREATS)

    def _stream_panel(self, records: List[PacketRecord], alerts: List[ThreatAlert]) -> Panel:
        """
        Build the live security event stream showing:
        - Timestamp
        - Protocol
        - Source IP:port
        - Destination IP:port
        - TCP flags
        - Size
        - Status/threat badge
        """
        if self.filter_state.mode == FilterMode.THREATS:
            return self._threat_stream_panel(alerts)

        table = Table.grid(padding=(0, 1), expand=True)
        table.add_column(width=8)   # Time
        table.add_column(width=5)   # Proto
        table.add_column(ratio=1)   # Src:port
        table.add_column(ratio=1)   # Dst:port
        table.add_column(width=4)   # Flags
        table.add_column(width=8, justify="right")  # Size

        recent = records[-self.config.live_stream_rows:]
        for r in reversed(recent):
            ts = datetime.fromtimestamp(r.timestamp).strftime("%H:%M:%S")
            proto_style = PROTOCOL_COLORS.get(r.protocol.value, "white")

            # Format source and destination with ports
            src = self._display_ip(r.src_ip)
            dst = self._display_ip(r.dst_ip)
            src_port = f":{r.src_port}" if r.src_port is not None else ""
            dst_port = f":{r.dst_port}" if r.dst_port is not None else ""

            flags = r.tcp_flags if r.tcp_flags else "-"

            table.add_row(
                Text(ts, style="grey62"),
                protocol_badge(r.protocol.value),
                Text(f"{src}{src_port}", style="cyan"),
                Text(f"{dst}{dst_port}", style="magenta"),
                Text(flags, style="yellow"),
                Text(format_bytes(r.size), style="grey70"),
            )

        if not recent:
            table.add_row(
                Text("--:--:--", style="grey50"),
                Text("---", style="grey50"),
                Text("waiting for packets...", style="grey50"),
                Text("", style="grey50"),
                Text("", style="grey50"),
                Text("", style="grey50"),
            )

        return Panel(table, title=f"{SYMBOL_PACKET} Live Security Event Stream", border_style=BORDER_STREAM)

    def _threat_stream_panel(self, alerts: List[ThreatAlert]) -> Panel:
        """Build the stream view used by THREATS mode."""
        table = Table.grid(padding=(0, 1), expand=True)
        table.add_column(width=8)
        table.add_column(width=10)
        table.add_column(width=8)
        table.add_column(ratio=1)
        table.add_column(ratio=1)

        for alert in reversed(alerts[-self.config.live_stream_rows:]):
            ts = datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")
            table.add_row(
                Text(ts, style="grey62"),
                severity_badge(alert.severity.value),
                Text(f"Risk {alert.risk_score}/100", style="bold yellow" if alert.risk_score >= 60 else "yellow"),
                Text(self._display_ip(alert.src_ip), style="cyan"),
                Text(alert.rule, style="white"),
            )

        if not alerts:
            table.add_row(
                Text("--:--:--", style="grey50"),
                Text("---", style="grey50"),
                Text(""),
                Text("No matching threat alerts", style="grey50"),
                Text(""),
            )

        return Panel(table, title=f"{SYMBOL_PACKET} Threat Event Stream", border_style=BORDER_STREAM)

    def _footer_panel(self, extra: str = "") -> Panel:
        """Build the footer with controls and queue info."""
        text = Text()
        text.append("Press ", style="grey50")
        text.append("Ctrl+C", style="bold white")
        text.append(" to stop and export session data", style="grey50")
        text.append("  |  ", style="grey35")
        text.append("[1] All  [2] Threats  [3] TCP  [4] UDP  [5] Hosts  [/] Search  [ESC] Clear  [Q] Quit", style="grey50")
        if extra:
            text.append(f"  |  {extra}", style="grey50")
        return Panel(Align.center(text), border_style=BORDER_FOOTER)

    # -- public render entrypoint ------------------------------------------

    def render(
        self,
        stats: StatsSnapshot,
        live_records: List[PacketRecord],
        watchlist: List[WatchlistEntry],
        alerts: List[ThreatAlert],
        incidents: Optional[List[Incident]] = None,
        footer_extra: str = "",
    ) -> Layout:
        """Render the complete dashboard layout."""
        incidents = incidents or []
        filtered_alerts = filter_alerts(alerts, self.filter_state)
        filtered_watchlist = filter_watchlist(watchlist, self.filter_state)
        filtered_incidents = filter_incidents(incidents, self.filter_state)
        filtered_records = filter_records(live_records, self.filter_state, filtered_alerts, filtered_watchlist)
        threat_count = len([a for a in filtered_alerts if a.severity in (Severity.HIGH, Severity.CRITICAL)])
        watchlist_count = len(filtered_watchlist)

        self.layout["header"].update(self._header_panel())
        self.layout["kpi_banner"].update(self._kpi_banner(stats, threat_count, watchlist_count))
        self.layout["search"].update(self._search_panel())
        self.layout["filter"].update(self._filter_panel())
        if self.filter_state.mode == FilterMode.HOSTS:
            self.layout["traffic"].update(self._host_activity_panel(stats, filtered_watchlist, filtered_alerts))
        else:
            self.layout["traffic"].update(self._traffic_panel(stats))
        self.layout["threats"].update(self._threats_panel(filtered_watchlist, filtered_alerts, filtered_incidents))
        self.layout["stream"].update(self._stream_panel(filtered_records, filtered_alerts))
        self.layout["footer"].update(self._footer_panel(footer_extra))
        return self.layout

    def make_live(self) -> Live:
        """Create a Rich Live display for real-time updates."""
        return Live(
            self.layout,
            console=self.console,
            refresh_per_second=self.config.refresh_per_second,
            screen=True,
        )
