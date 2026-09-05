# NETWORK ANALYZER

Real-Time Network Traffic Analyzer & Behavioral NIDS

by Shubh070705

NETWORK ANALYZER is a Python terminal application for watching live network traffic, summarizing packet activity, and flagging suspicious behavior with simple heuristic detection rules. It is meant for learning, lab use, and portfolio demonstration on systems and networks you are allowed to monitor.

## About

The application captures packets with Scapy, parses header metadata into normalized packet records, updates rolling traffic statistics, runs detection rules, assigns each alert a 0-100 risk score, and renders the session in a Rich terminal dashboard.

It writes packet and alert summaries to CSV and can save a PCAP file for later review in Wireshark. The dashboard can also mask IP addresses for demos or screen recordings.

## Features

- Live packet capture
- Packet analysis for TCP, UDP, ICMP, and other IP traffic
- Rolling packets/sec, bytes/sec, and average packet size
- Protocol distribution
- Top hosts and top talkers
- Live packet stream
- Threat detection
- 0-100 heuristic risk scoring
- Watchlist of recently suspicious hosts
- Incident correlation for related alerts
- CSV logging
- PCAP capture/export
- Rich terminal dashboard
- Optional on-screen IP masking

## Detection Rules

The detection engine currently includes these rules:

- `NET-001` TCP SYN Scan: flags one source sending bare SYN packets to many destination ports in a short window.
- `NET-002` Port Scan: flags one source contacting many destination ports on the same target.
- `NET-003` ICMP Sweep: flags one source sending ICMP probes to many destination hosts.
- `NET-004` Possible SYN Flood / Abnormal SYN Activity: flags high SYN volume globally or between one source and destination.
- `NET-005` Traffic Spike: flags packet-rate spikes compared with a rolling baseline.
- `NET-006` DNS Request Anomaly: flags high DNS request volume from one source or across the session.
- `NET-007` Unusual Port Activity: flags repeated contact with multiple uncommon destination ports.

These rules are heuristics. They identify patterns worth investigating, not proof of compromise.

## Risk Scoring

Alerts receive a deterministic risk score from 0 to 100. The score starts with a base value for the rule, then adds small bonuses for stronger evidence such as more ports, more hosts, more events, or multiple rule types from the same source.

Risk scores are only for prioritization:

- `0-29`: low
- `30-59`: medium
- `60-79`: high
- `80-100`: critical

The score is not machine learning and does not mean probability of compromise.

## Architecture

```text
Packet Capture
  -> Analyzer
  -> Statistics / Detection
  -> Risk Scoring
  -> Incident Correlation
  -> Dashboard / Export
```

Main components:

- `main.py`: command-line entry point and application wiring
- `config.py`: environment-aware settings and thresholds
- `core/capture.py`: Scapy capture thread
- `core/analyzer.py`: packet parsing and fan-out
- `core/statistics.py`: rolling traffic statistics
- `detection/`: detection rules, risk scoring, and watchlist handling
- `incident/`: related alert grouping
- `dashboard/`: Rich terminal UI
- `exporters/`: CSV and PCAP output
- `tests/`: unit tests using synthetic packet records

## Installation

```bash
git clone https://github.com/Shubh070705/Network-traffic-analyzer.git
cd Network-traffic-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows, activate the virtual environment with:

```bash
.venv\Scripts\activate
```

## Running

```bash
python3 main.py
```

Useful options:

```bash
python3 main.py --list-interfaces
python3 main.py --interface eth0
python3 main.py --interface eth0 --bpf "tcp or udp"
python3 main.py --interface eth0 --mask-ips
python3 main.py --interface eth0 --max-packets 5000
python3 main.py --interface eth0 --syn-scan-threshold 10 --port-scan-threshold 25
python3 main.py --interface eth0 --no-pcap --no-csv
```

Press `Ctrl+C` to stop the session cleanly.

## macOS / Linux / Windows

Live packet capture usually requires elevated permissions.

On Linux, run with `sudo`:

```bash
sudo python3 main.py
```

Or grant raw packet capabilities to your Python interpreter:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

On Windows, install Npcap in WinPcap API-compatible mode and run the terminal as Administrator.

On macOS, you may need to run with administrator privileges depending on the interface and packet capture permissions.

## Output

By default, runtime output is written to:

- `logs/session_events.csv`
- `captures/session_capture.pcap`

The CSV contains packet metadata and alert summaries. The PCAP contains captured packets so it can be opened in Wireshark.

## Testing

```bash
python3 -m unittest discover -s tests -v
```

The tests use synthetic packet records for detection and statistics. Packet parsing tests are skipped if Scapy is not available.

## Limitations

- Detection is heuristic and can produce false positives.
- The analyzer uses packet headers for statistics and detection, not payload inspection.
- PCAP export stores full packets because that is required for Wireshark-compatible captures.
- Live capture depends on OS permissions and Scapy/libpcap/Npcap support.
- Offline PCAP investigation is not a separate workflow yet.
- Thresholds may need tuning for busy or unusual networks.

## Author

by Shubh070705
