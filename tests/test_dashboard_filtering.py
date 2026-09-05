"""Unit tests for dashboard filtering and keyboard mode state."""

from __future__ import annotations

import unittest

from core.models import PacketRecord, Protocol, Severity, ThreatAlert, WatchlistEntry
from dashboard.filtering import (
    ALL,
    DashboardFilterState,
    FilterMode,
    build_host_activity,
    filter_alerts,
    filter_host_activity,
    filter_records,
    filter_watchlist,
)
from dashboard.keyboard import KeyboardController


def make_record(
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    protocol=Protocol.TCP,
    timestamp=1.0,
    dst_port=80,
):
    return PacketRecord(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        size=100,
        src_port=12345,
        dst_port=dst_port,
        tcp_flags="S" if protocol == Protocol.TCP else None,
        ttl=64,
    )


def make_alert(
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    rule="NET-002",
    severity=Severity.HIGH,
    risk_score=78,
):
    return ThreatAlert(
        timestamp=2.0,
        rule=rule,
        severity=severity,
        src_ip=src_ip,
        dst_ip=dst_ip,
        detail="test alert",
        evidence_count=5,
        risk_score=risk_score,
    )


class TestDashboardFilterState(unittest.TestCase):
    def test_default_all_mode(self):
        state = DashboardFilterState()

        self.assertEqual(state.mode, FilterMode.ALL)
        self.assertEqual(state.protocol, ALL)
        self.assertEqual(state.severity, ALL)
        self.assertEqual(state.host, ALL)
        self.assertEqual(state.rule, ALL)
        self.assertFalse(state.quit_requested)

    def test_shortcut_modes(self):
        state = DashboardFilterState()

        state.apply_shortcut("2")
        self.assertEqual(state.mode, FilterMode.THREATS)

        state.apply_shortcut("3")
        self.assertEqual(state.mode, FilterMode.TCP)
        self.assertEqual(state.protocol, "TCP")

        state.apply_shortcut("4")
        self.assertEqual(state.mode, FilterMode.UDP)
        self.assertEqual(state.protocol, "UDP")

        state.apply_shortcut("5")
        self.assertEqual(state.mode, FilterMode.HOSTS)

        state.apply_shortcut("1")
        self.assertEqual(state.mode, FilterMode.ALL)
        self.assertEqual(state.protocol, ALL)

    def test_unknown_shortcuts_and_filter_values_are_ignored(self):
        state = DashboardFilterState()

        state.apply_shortcut("x")
        state.set_mode("bad")
        state.set_protocol("smtp")
        state.set_severity("urgent")

        self.assertEqual(state.mode, FilterMode.ALL)
        self.assertEqual(state.protocol, ALL)
        self.assertEqual(state.severity, ALL)

    def test_graceful_quit_shortcut(self):
        state = DashboardFilterState()

        state.apply_shortcut("q")

        self.assertTrue(state.quit_requested)

    def test_clear_search_shortcut(self):
        state = DashboardFilterState(search="10.0.0.1")

        state.apply_shortcut("\x1b")

        self.assertEqual(state.search, ALL)
        self.assertFalse(state.has_search)

    def test_search_input_shortcut(self):
        state = DashboardFilterState()

        state.apply_shortcut("/")
        state.apply_shortcut("T")
        state.apply_shortcut("C")
        state.apply_shortcut("P")
        state.apply_shortcut("\r")

        self.assertEqual(state.search, "TCP")
        self.assertFalse(state.search_active)


class TestKeyboardSearchInput(unittest.TestCase):
    def test_keyboard_bytes_enter_search_and_type_text(self):
        state = DashboardFilterState()
        keyboard = KeyboardController(state)

        keyboard.apply_input_bytes(b"/192.168.1.44\r")

        self.assertEqual(state.search, "192.168.1.44")
        self.assertFalse(state.search_active)

    def test_keyboard_bytes_treat_shortcut_keys_as_search_text_while_typing(self):
        state = DashboardFilterState()
        keyboard = KeyboardController(state)

        keyboard.apply_input_bytes(b"/TCP 443")

        self.assertEqual(state.search, "TCP 443")
        self.assertTrue(state.search_active)
        self.assertEqual(state.mode, FilterMode.ALL)
        self.assertEqual(state.protocol, ALL)

    def test_keyboard_bytes_backspace_and_escape_clear_search(self):
        state = DashboardFilterState()
        keyboard = KeyboardController(state)

        keyboard.apply_input_bytes(b"/NET-003\x7f2\r")
        self.assertEqual(state.search, "NET-002")

        keyboard.apply_input_bytes(b"/HIGH\x1b")
        self.assertEqual(state.search, ALL)
        self.assertFalse(state.search_active)

    def test_keyboard_shortcuts_still_work_outside_search(self):
        state = DashboardFilterState()
        keyboard = KeyboardController(state)

        keyboard.apply_input_bytes(b"345q")

        self.assertEqual(state.mode, FilterMode.HOSTS)
        self.assertEqual(state.protocol, ALL)
        self.assertTrue(state.quit_requested)


class TestDashboardFiltering(unittest.TestCase):
    def setUp(self):
        self.records = [
            make_record(src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol=Protocol.TCP),
            make_record(src_ip="10.0.0.3", dst_ip="10.0.0.4", protocol=Protocol.UDP),
            make_record(src_ip="10.0.0.5", dst_ip="10.0.0.6", protocol=Protocol.ICMP),
        ]
        self.alerts = [
            make_alert(src_ip="10.0.0.1", dst_ip="10.0.0.2", rule="NET-002", severity=Severity.HIGH),
            make_alert(src_ip="10.0.0.3", dst_ip="10.0.0.4", rule="NET-006", severity=Severity.MEDIUM, risk_score=40),
        ]
        self.watchlist = [
            WatchlistEntry(
                ip="10.0.0.1",
                last_seen=2.0,
                highest_severity=Severity.HIGH,
                reasons=["NET-002"],
                alert_count=4,
                highest_risk_score=78,
            )
        ]

    def test_all_filter_returns_all_records_and_alerts(self):
        state = DashboardFilterState()

        self.assertEqual(filter_records(self.records, state, self.alerts, self.watchlist), self.records)
        self.assertEqual(filter_alerts(self.alerts, state), self.alerts)

    def test_threats_filter_limits_records_to_threat_hosts(self):
        state = DashboardFilterState(mode=FilterMode.THREATS)

        records = filter_records(self.records, state, [self.alerts[0]], self.watchlist)

        self.assertEqual(records, [self.records[0]])

    def test_tcp_filter(self):
        state = DashboardFilterState()
        state.apply_shortcut("3")

        records = filter_records(self.records, state)

        self.assertEqual(records, [self.records[0]])

    def test_udp_filter(self):
        state = DashboardFilterState()
        state.apply_shortcut("4")

        records = filter_records(self.records, state)

        self.assertEqual(records, [self.records[1]])

    def test_hosts_mode_builds_host_activity(self):
        state = DashboardFilterState()
        state.apply_shortcut("5")

        rows = build_host_activity([("10.0.0.5", 12), ("10.0.0.1", 6)], self.watchlist, self.alerts)

        self.assertEqual(state.mode, FilterMode.HOSTS)
        self.assertEqual(rows[0].ip, "10.0.0.1")
        self.assertEqual(rows[0].risk_score, 78)
        self.assertEqual(rows[0].alert_count, 4)

    def test_protocol_filtering(self):
        state = DashboardFilterState()
        state.set_protocol("ICMP")

        records = filter_records(self.records, state)

        self.assertEqual(records, [self.records[2]])

    def test_severity_filtering(self):
        state = DashboardFilterState()
        state.set_severity("medium")

        alerts = filter_alerts(self.alerts, state)

        self.assertEqual(alerts, [self.alerts[1]])

    def test_host_filtering(self):
        state = DashboardFilterState()
        state.set_host("10.0.0.4")

        records = filter_records(self.records, state)
        alerts = filter_alerts(self.alerts, state)

        self.assertEqual(records, [self.records[1]])
        self.assertEqual(alerts, [self.alerts[1]])

    def test_rule_filtering(self):
        state = DashboardFilterState()
        state.set_rule("NET-006")

        alerts = filter_alerts(self.alerts, state)

        self.assertEqual(alerts, [self.alerts[1]])

    def test_rule_alias_filtering(self):
        state = DashboardFilterState()
        state.set_rule("PORT_SCAN")

        alerts = filter_alerts(self.alerts, state)

        self.assertEqual(state.rule, "NET-002")
        self.assertEqual(alerts, [self.alerts[0]])

    def test_combined_filters(self):
        state = DashboardFilterState(protocol="TCP", severity="HIGH", host="10.0.0.1", rule="NET-002")

        records = filter_records(self.records, state)
        alerts = filter_alerts(self.alerts, state)
        watchlist = filter_watchlist(self.watchlist, state)

        self.assertEqual(records, [self.records[0]])
        self.assertEqual(alerts, [self.alerts[0]])
        self.assertEqual(watchlist, self.watchlist)

    def test_unknown_host_or_rule_filters_do_not_crash(self):
        state = DashboardFilterState(host="192.0.2.50", rule="NET-999")

        self.assertEqual(filter_records(self.records, state), [])
        self.assertEqual(filter_alerts(self.alerts, state), [])
        self.assertEqual(filter_watchlist(self.watchlist, state), [])

    def test_exact_search(self):
        state = DashboardFilterState(search="10.0.0.1")

        self.assertEqual(filter_records(self.records, state), [self.records[0]])
        self.assertEqual(filter_alerts(self.alerts, state), [self.alerts[0]])
        self.assertEqual(filter_watchlist(self.watchlist, state), self.watchlist)

    def test_partial_search(self):
        state = DashboardFilterState(search="10.0.0")

        self.assertEqual(filter_records(self.records, state), self.records)
        self.assertEqual(filter_alerts(self.alerts, state), self.alerts)

    def test_case_insensitive_search(self):
        self.alerts[0].detail = "Suspicious Port Scan activity"
        state = DashboardFilterState(search="port scan")

        self.assertEqual(filter_alerts(self.alerts, state), [self.alerts[0]])

    def test_ip_search(self):
        state = DashboardFilterState(search="10.0.0.4")

        self.assertEqual(filter_records(self.records, state), [self.records[1]])
        self.assertEqual(filter_alerts(self.alerts, state), [self.alerts[1]])

    def test_protocol_search(self):
        state = DashboardFilterState(search="udp")

        self.assertEqual(filter_records(self.records, state), [self.records[1]])

    def test_rule_search(self):
        state = DashboardFilterState(search="PORT_SCAN")

        self.assertEqual(filter_alerts(self.alerts, state), [self.alerts[0]])
        self.assertEqual(filter_watchlist(self.watchlist, state), self.watchlist)

    def test_severity_search(self):
        state = DashboardFilterState(search="medium")

        self.assertEqual(filter_alerts(self.alerts, state), [self.alerts[1]])

        rows = build_host_activity([("10.0.0.5", 12), ("10.0.0.1", 6)], self.watchlist, self.alerts)
        state.set_search("high")
        self.assertEqual([row.ip for row in filter_host_activity(rows, state)], ["10.0.0.1"])

    def test_combined_search_and_filters(self):
        state = DashboardFilterState(protocol="TCP", severity="HIGH", rule="NET-002", search="10.0.0.1")

        self.assertEqual(filter_records(self.records, state), [self.records[0]])
        self.assertEqual(filter_alerts(self.alerts, state), [self.alerts[0]])
        self.assertEqual(filter_watchlist(self.watchlist, state), self.watchlist)

        state.set_search("10.0.0.3")
        self.assertEqual(filter_records(self.records, state), [])
        self.assertEqual(filter_alerts(self.alerts, state), [])

    def test_clearing_search_restores_all_search_results(self):
        state = DashboardFilterState(search="10.0.0.1")
        self.assertEqual(filter_records(self.records, state), [self.records[0]])

        state.clear_search()

        self.assertEqual(state.search, ALL)
        self.assertEqual(filter_records(self.records, state), self.records)


if __name__ == "__main__":
    unittest.main()
