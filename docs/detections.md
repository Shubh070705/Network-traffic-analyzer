# NETWORK ANALYZER Detection Rules

This document describes the current heuristic detection rules in NETWORK ANALYZER.

All detection rules are **heuristics**. They flag network traffic patterns consistent with scanning, reconnaissance, anomalies, or flooding. They operate strictly on packet header metadata captured by the analyzer. They do not prove malicious intent and can produce false positives on legitimate bursty traffic.

---

## Architecture Overview

```
PacketRecord -> DetectionEngine -> Detector Rules -> ThreatAlert -> Risk Scoring -> Incident Correlation
```

- **`BaseDetector` (`detection/base.py`)**: Shared interface defining rule properties (`rule_id`, `rule_name`), packet evaluation (`observe`), state reset (`reset`), and state cleanup (`cleanup_state`).
- **`DetectionEngine` (`detection/engine.py`)**: Runs active detectors against incoming packets, scores alerts, updates the watchlist, correlates incidents, logs recent alerts, and triggers periodic state cleanup every 500 packets.
- **`RiskScorer` (`detection/risk.py`)**: Assigns 0-100 heuristic risk scores for prioritizing alerts.
- **`IncidentCorrelator` (`incident/correlator.py`)**: Groups related alerts by source and destination into bounded incident history.
- **Alert Deduplication & Cooldown**: Each detector enforces a per-source or per-flow cooldown period (default 5.0 seconds) to prevent alert spam during continuous activity.

---

## Detection Rules Reference

### NET-001 — TCP SYN Scan

- **Detection Name**: TCP SYN Scan
- **Rule ID**: `NET-001`
- **Detector Class**: `SynScanDetector` (`detection/syn_scan.py`)
- **What it detects**: A single source IP sending bare TCP SYN packets (SYN set, ACK not set) to multiple distinct destination ports within a sliding time window.
- **Key Thresholds**:
  - `syn_scan_port_threshold`: 15 unique destination ports (default)
  - `syn_scan_window_seconds`: 5.0 seconds (default)
- **Alert Escalation**: LOW (>= threshold), MEDIUM (>= 1.5x), HIGH (>= 2.5x)
- **Evidence Provided**: Unique port count, time window, sample ports.
- **Potential False Positives**: Connection-pooling clients, legitimate vulnerability scanners, port-knocking tools.
- **Limitations**: Does not track TCP handshake completions.

---

### NET-002 — Port Scan

- **Detection Name**: Port Scan
- **Rule ID**: `NET-002`
- **Detector Class**: `PortScanDetector` (`detection/port_scan.py`)
- **What it detects**: A single source IP contacting many distinct destination ports on a single target destination IP within a sliding time window.
- **Key Thresholds**:
  - `port_scan_port_threshold`: 20 unique destination ports (default)
  - `port_scan_window_seconds`: 10.0 seconds (default)
- **Alert Escalation**: LOW (>= threshold), MEDIUM (>= 1.5x), HIGH (>= 2.5x)
- **Evidence Provided**: Unique port count, target IP, time window.
- **Potential False Positives**: Multi-service health checks, monitoring agents.
- **Limitations**: Evaluates destination ports regardless of protocol or TCP flags.

---

### NET-003 — ICMP Sweep

- **Detection Name**: ICMP Sweep
- **Rule ID**: `NET-003`
- **Detector Class**: `IcmpSweepDetector` (`detection/icmp_sweep.py`)
- **What it detects**: A single source IP sending ICMP traffic to multiple unique destination host IPs within a sliding time window.
- **Key Thresholds**:
  - `icmp_sweep_host_threshold`: 10 unique target hosts (default)
  - `icmp_sweep_window_seconds`: 30.0 seconds (default)
- **Severity**: `MEDIUM`
- **Evidence Provided**: Unique destination host count, time window, target host samples.
- **Potential False Positives**: Network discovery tools, ping monitoring suites.
- **Limitations**: Tracks ICMP at the protocol level; the normalized packet record does not currently keep ICMP type/code.

---

### NET-004 — Possible SYN Flood / Abnormal SYN Rate

- **Detection Name**: Possible SYN Flood / Abnormal SYN Activity
- **Rule ID**: `NET-004`
- **Detector Class**: `SynFloodDetector` (`detection/syn_flood.py`)
- **What it detects**: Unusually high volume of TCP SYN packets within a short sliding time window, evaluated both globally and per (src, dst) pair.
- **Key Thresholds**:
  - `syn_flood_packet_threshold`: 100 SYN packets (default)
  - `syn_flood_window_seconds`: 10.0 seconds (default)
- **Severity**: `HIGH`
- **Evidence Provided**: Global SYN count, pair SYN count, time window.
- **Potential False Positives**: Flash crowds, heavy bursty traffic.
- **Limitations**: Labeled as "possible" because packet metadata does not include full TCP stateful session tables.

---

### NET-005 — Traffic Spike

- **Detection Name**: Traffic Spike
- **Rule ID**: `NET-005`
- **Detector Class**: `TrafficSpikeDetector` (`detection/traffic_spike.py`)
- **What it detects**: Sudden, abnormal increases in overall network packet rate compared against a rolling baseline.
- **Key Thresholds**:
  - `traffic_spike_multiplier`: 5.0x baseline rate (default)
  - `traffic_spike_window_seconds`: 10.0 seconds (default)
- **Severity**: `MEDIUM`
- **Evidence Provided**: Baseline packets/sec, current packets/sec, spike multiplier.
- **Potential False Positives**: Large file transfers, backup operations.
- **Limitations**: Requires minimum packet count before establishing baseline.

---

### NET-006 — DNS Request Anomaly

- **Detection Name**: DNS Request Anomaly
- **Rule ID**: `NET-006`
- **Detector Class**: `DnsAnomalyDetector` (`detection/dns_anomaly.py`)
- **What it detects**: Unusually high rates of DNS requests (destination port 53 UDP/TCP) from a single source or network-wide.
- **Key Thresholds**:
  - `dns_anomaly_request_threshold`: 50 requests per source (default)
  - `dns_anomaly_window_seconds`: 10.0 seconds (default)
- **Severity**: `MEDIUM`
- **Evidence Provided**: Request count, time window, source IP.
- **Potential False Positives**: Local DNS resolvers, heavy web browsing.
- **Limitations**: Inspects header metadata (port 53) only; does not store DNS payload.

---

### NET-007 — Unusual Port Activity

- **Detection Name**: Unusual Port Activity
- **Rule ID**: `NET-007`
- **Detector Class**: `UnusualPortDetector` (`detection/unusual_port.py`)
- **What it detects**: Repeated connection attempts to non-standard, uncommon destination ports (excluding well-known ports and high ephemeral ports >= 49152).
- **Key Thresholds**:
  - `unusual_port_threshold`: 5 unique unusual ports (default)
  - `unusual_port_window_seconds`: 60.0 seconds (default)
- **Severity**: `LOW`
- **Evidence Provided**: Connection count, unique unusual port count, sample ports.
- **Potential False Positives**: Custom enterprise software on non-standard ports.
- **Limitations**: Only flags when multiple connections to multiple non-standard ports occur.

---

## State Cleanup

1. **Sliding Window Pruning**: Every detector purges timestamped events older than its configured time window.
2. **Periodic Cleanup Pass**: `DetectionEngine` calls `cleanup_state(now)` every 500 packets.
3. **Watchlist Expiration**: Entries expire after `watchlist_ttl_seconds` (default 300.0s).
4. **Incident History Limit**: Correlated incidents are kept in bounded in-memory history.

## Incident Correlation

Incident correlation groups alerts that share the same source and destination while they are still inside the watchlist TTL window. Each incident has a sequential ID, status, first/last seen timestamps, rule set, alert count, highest risk score, severity, and a short evidence list.

This is an in-memory investigation aid. It is not a database and does not perform offline PCAP investigation.
