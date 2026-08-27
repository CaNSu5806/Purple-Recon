# 🟣 PurpleRecon

<!-- ===================================================== -->
<!-- HEADER -->
<!-- ===================================================== -->

![PurpleRecon Header](https://capsule-render.vercel.app/api?type=waving&height=220&color=0:8A2BE2,50:FF0055,100:00BFFF&text=PurpleRecon&fontColor=ffffff&fontSize=42&animation=twinkling&desc=Reconnaissance%20%7C%20Traffic%20Analysis%20%7C%20Detection%20Correlation&descAlignY=72)

<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&size=19&pause=1200&color=8A2BE2&center=true&vCenter=true&width=900&lines=Reconnaissance+from+an+attacker's+perspective...;Analyzing+the+network+footprint+left+behind...;Connecting+offensive+activity+with+defensive+visibility...;One+workflow.+Two+perspectives.+PurpleRecon." />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Project-Purple%20Team-8A2BE2?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Version-v1.0-FF0055?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Core-Python-00BFFF?style=for-the-badge&logo=python&logoColor=white" />
</p>

---

## 🟣 Project Overview

**PurpleRecon** is a Python-based Purple Team reconnaissance and network analysis tool designed to connect two different security perspectives:

🔴 **What can an attacker discover about a target?**

🔵 **What network traces does that reconnaissance activity leave behind?**

Instead of treating reconnaissance and detection as completely separate processes, PurpleRecon collects, analyzes, and correlates information from both sides.

The project combines:

- Active network reconnaissance
- Service enumeration
- Contextual risk analysis
- MITRE ATT&CK context
- PCAP/PCAPNG traffic analysis
- TCP SYN scan-pattern detection
- Offensive/defensive correlation
- JSON and HTML reporting

The main objective is not exploitation.

PurpleRecon focuses on understanding the relationship between **reconnaissance activity and defensive visibility**.

---

# 🔴 Offensive Perspective

PurpleRecon uses **Nmap** as its reconnaissance engine.

The tool executes configurable scans and processes the resulting XML output instead of treating Nmap output as plain terminal text.

The reconnaissance pipeline is:

```text
Target
  │
  ▼
Nmap
  │
  ▼
XML Output
  │
  ▼
Nmap Parser
  │
  ├── Open Ports
  ├── Protocols
  ├── Services
  ├── Products
  └── Versions
```

PurpleRecon converts these results into structured Python/JSON data for further analysis.

Example:

```json
{
    "port": 3306,
    "protocol": "tcp",
    "state": "open",
    "service": "mysql",
    "product": "MySQL",
    "version": "8.0.43"
}
```

---

# 🟡 Contextual Risk Analysis

Discovering an open port alone does not explain why it may matter.

PurpleRecon includes a contextual risk-analysis layer that evaluates discovered services and produces structured findings.

The purpose of this module is to add security context to reconnaissance results rather than automatically declaring a service vulnerable.

```text
Discovered Service
       │
       ▼
  Risk Analyzer
       │
       ▼
Contextual Finding
```

This distinction is important:

> An exposed service may increase attack surface, but an open port alone does not prove the existence of a vulnerability.

---

# 🧭 MITRE ATT&CK Context

Reconnaissance results can also be passed through the ATT&CK mapping layer.

This allows PurpleRecon to associate discovered network behavior and services with relevant security context.

```text
Reconnaissance
      │
      ▼
Service Analysis
      │
      ▼
ATT&CK Context
```

The goal is to make reconnaissance results more useful from a defensive and Purple Team perspective.

---

# 🔵 Defensive Perspective

PurpleRecon also analyzes network captures using **TShark**.

Supported capture formats include:

```text
.pcap
.pcapng
```

The defensive pipeline is:

```text
PCAP / PCAPNG
      │
      ▼
    TShark
      │
      ▼
Raw Packet Fields
      │
      ▼
  PCAP Parser
      │
      ▼
Normalized Packets
      │
      ▼
Detection Analysis
```

The parser currently extracts fields such as:

- Timestamp
- Source IP
- Destination IP
- Protocol
- Source port
- Destination port
- TCP flags

This converts packet-level information into structured data that can be processed by PurpleRecon's detection modules.

---

# 🔍 TCP SYN Scan-Pattern Detection

PurpleRecon includes a basic network scan detector.

The detector analyzes TCP SYN activity and tracks how many distinct destination ports a source contacts on the same destination host.

Conceptually:

```text
Source
  │
  ├── SYN → Port 22
  ├── SYN → Port 80
  ├── SYN → Port 443
  ├── SYN → Port 445
  └── SYN → Port 3306
              │
              ▼
       Scan Pattern Analysis
```

When the configured threshold is reached, PurpleRecon can generate a finding such as:

```json
{
    "event_type": "possible_syn_scan",
    "source_ip": "10.0.0.5",
    "destination_ip": "10.0.0.10",
    "distinct_destination_ports": 5,
    "ports": [
        22,
        80,
        443,
        445,
        3306
    ],
    "severity": "medium"
}
```

PurpleRecon intentionally describes this as a **possible scan pattern**, rather than claiming that every matching pattern is malicious.

---

# 🟣 Offensive / Defensive Correlation

This is the core Purple Team capability of PurpleRecon.

The correlation engine compares ports observed during defensive PCAP analysis with services independently confirmed as open by Nmap.

For example:

```text
Nmap Results
────────────
22   OPEN
80   OPEN
3306 OPEN


PCAP Scan Observation
─────────────────────
22
80
443
445


        │
        ▼

Correlation Engine

        │
        ▼

Matched Ports
─────────────
22
80
```

This connects two perspectives:

| 🔴 Offensive | 🔵 Defensive |
|---|---|
| Which services are exposed? | Which ports were contacted? |
| What does reconnaissance discover? | What traffic does reconnaissance generate? |
| What does Nmap observe? | What does packet analysis observe? |
| What attack surface exists? | What evidence is visible to defenders? |

The resulting correlation can be represented as structured data:

```json
{
    "source_ip": "10.0.0.5",
    "destination_ip": "10.0.0.10",
    "observed_scan_ports": [
        22,
        80,
        443,
        445
    ],
    "confirmed_open_ports": [
        22,
        80,
        3306
    ],
    "matched_ports": [
        22,
        80
    ],
    "matched_port_count": 2
}
```

---

# 🟣 Unified Purple Team Report

PurpleRecon combines its analysis layers into a unified report.

```text
                         PurpleRecon
                              │
              ┌───────────────┴───────────────┐
              │                               │
        🔴 Reconnaissance               🔵 Detection
              │                               │
            Nmap                            TShark
              │                               │
         Nmap Parser                     PCAP Parser
              │                               │
       Service Analysis                 Scan Detector
              │                               │
       Risk + ATT&CK                         │
              │                               │
              └───────────────┬───────────────┘
                              │
                              ▼
                         Correlation
                              │
                              ▼
                    🟣 Purple Team Report
                         │             │
                         ▼             ▼
                       JSON           HTML
```

The unified report contains:

- Target information
- Nmap reconnaissance results
- Security events
- Contextual risk findings
- ATT&CK mappings
- PCAP statistics
- Detected scan patterns
- Offensive/defensive correlations

---

# 📊 Reporting

PurpleRecon produces multiple output layers rather than storing everything in a single file.

Depending on the selected command, output can include:

```text
output/
│
├── scan_<target>_<timestamp>.json
├── events_<target>_<timestamp>.json
├── risk_<target>_<timestamp>.json
├── attack_<target>_<timestamp>.json
├── report_<target>_<timestamp>.json
├── report_<target>_<timestamp>.html
│
├── pcap_packets_pcap_<timestamp>.json
├── pcap_findings_pcap_<timestamp>.json
├── pcap_report_pcap_<timestamp>.json
│
├── correlation_<target>_<timestamp>.json
├── purple_report_<target>_<timestamp>.json
└── purple_report_<target>_<timestamp>.html
```

Generated output is ignored by Git by default.

---

# ⚙️ Configuration

PurpleRecon uses YAML configuration to keep scanner behavior separate from application logic.

Configuration is loaded from:

```text
configs/config.yaml
```

This allows scan behavior to be modified without changing the Python source code.

---

# 💻 Command-Line Interface

PurpleRecon currently provides three main workflows.

## 1. Reconnaissance Scan

Run active reconnaissance against a target:

```bash
python main.py scan 127.0.0.1
```

Pipeline:

```text
Nmap
 → Parser
 → Security Events
 → Risk Analysis
 → ATT&CK Context
 → JSON Report
 → HTML Report
```

---

## 2. PCAP Analysis

Analyze an existing packet capture:

```bash
python main.py analyze-pcap sample.pcapng
```

Pipeline:

```text
PCAP
 → TShark
 → PCAP Parser
 → Scan Detection
 → Defensive Report
```

A capture containing no matching reconnaissance pattern may legitimately produce:

```json
[]
```

This means no activity exceeded the current detection criteria; it does not necessarily indicate an analysis failure.

---

## 3. Purple Team Correlation

Combine active reconnaissance with defensive packet observations:

```bash
python main.py correlate 127.0.0.1 sample.pcapng
```

Pipeline:

```text
Nmap Recon ─────────┐
                    │
                    ├── Correlation
                    │        │
PCAP Analysis ──────┘        ▼
                      Purple Team Report
```

Correlation results can be empty when the supplied capture does not contain scan-like activity matching the configured detection threshold.

---

# 📁 Project Structure

```text
Purple-Recon/
│
├── main.py
│
├── purple_recon/
│   │
│   ├── __init__.py
│   │
│   ├── recon/
│   │   ├── __init__.py
│   │   ├── nmap.py
│   │   └── tshark.py
│   │
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── nmap_parser.py
│   │   └── pcap_parser.py
│   │
│   ├── generators/
│   │   ├── __init__.py
│   │   └── event_generator.py
│   │
│   ├── analysis/
│   │   ├── __init__.py
│   │   ├── risk_analyzer.py
│   │   ├── attack_mapper.py
│   │   ├── scan_detector.py
│   │   └── correlator.py
│   │
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── report_builder.py
│   │   ├── html_report.py
│   │   ├── pcap_report_builder.py
│   │   └── purple_html_report.py
│   │
│   └── utils/
│       ├── __init__.py
│       ├── config_loader.py
│       └── output_manager.py
│
├── configs/
│   └── config.yaml
│
├── tests/
│   ├── test_nmap_parser.py
│   ├── test_scan_detector.py
│   └── test_correlator.py
│
├── output/
│
├── pytest.ini
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

---

# 📦 Requirements

## System Requirements

PurpleRecon relies on external networking tools that must be installed separately:

- Python 3.12+
- Nmap
- Wireshark / TShark
- Npcap on Windows

Verify Nmap:

```bash
nmap --version
```

Verify TShark:

```bash
tshark --version
```

---

## Python Dependencies

Create a virtual environment:

### Windows

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Linux

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Current Python dependency:

```text
PyYAML
```

For development/testing, install `pytest` if it is not already available:

```bash
pip install pytest
```

---

# 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/CaNSu5806/Purple-Recon.git
cd Purple-Recon
```

Create and activate a virtual environment, then install the Python dependencies:

```bash
pip install -r requirements.txt
```

Make sure both Nmap and TShark are accessible through the system `PATH`.

Check the PurpleRecon CLI:

```bash
python main.py --help
```

Expected commands include:

```text
scan
analyze-pcap
correlate
```

---

# 🧪 Testing

PurpleRecon includes unit tests for important analysis components.

Run all tests with:

```bash
pytest -v
```

Current tests cover areas such as:

- Nmap XML parsing
- SYN scan detection
- Normal traffic false-positive behavior
- Repeated SYN handling
- Nmap/PCAP correlation

The scan detector is tested not only for detecting scan-like activity, but also for avoiding simple false positives such as repeated SYN packets to a single destination port.

---

# 🛡️ Security Design Principles

PurpleRecon follows several principles throughout the project:

### Structured Data Over Terminal Text

Tool output is parsed into structured Python objects before analysis.

### Separation of Responsibilities

Reconnaissance, parsing, detection, analysis, correlation, configuration, and reporting are implemented as separate modules.

### Context Instead of Assumptions

An open service is not automatically labeled as vulnerable.

A SYN pattern is not automatically labeled as malicious.

Findings provide context rather than unsupported conclusions.

### Defensive Visibility

Reconnaissance is analyzed not only by what it discovers, but also by what evidence it leaves behind.

---

# 🧠 What This Project Demonstrates

PurpleRecon was built as a practical cybersecurity engineering project rather than only a collection of tool commands.

The project demonstrates experience with:

- Python project architecture
- Modular software design
- CLI development with `argparse`
- Python `subprocess`
- Nmap automation
- Nmap XML parsing
- TShark integration
- PCAP/PCAPNG analysis
- TCP fundamentals
- TCP flag analysis
- Basic network scan detection
- Security-event normalization
- Contextual risk analysis
- MITRE ATT&CK context
- Offensive/defensive data correlation
- JSON serialization
- HTML report generation
- YAML configuration
- Unit testing with `pytest`
- Git/GitHub development workflow

Most importantly, PurpleRecon demonstrates the idea that:

> **Reconnaissance can be studied from both the attacker's and the defender's perspective.**

---

# 🗺️ Development Status

## ✅ PurpleRecon v1

- [x] Nmap integration
- [x] Nmap XML parsing
- [x] Service enumeration
- [x] Structured scan results
- [x] Security-event generation
- [x] Contextual risk analysis
- [x] MITRE ATT&CK context
- [x] YAML configuration
- [x] JSON reporting
- [x] HTML reporting
- [x] TShark integration
- [x] PCAP/PCAPNG parsing
- [x] TCP SYN scan-pattern detection
- [x] PCAP reporting
- [x] Nmap/PCAP correlation
- [x] Unified Purple Team JSON report
- [x] Unified Purple Team HTML report
- [x] CLI subcommands
- [x] Unit tests

## 🔮 Possible Future Development

Potential future versions may explore:

- [ ] Additional TCP scan-pattern detection
- [ ] Detection timing/window analysis
- [ ] Advanced PCAP statistics
- [ ] IDS-oriented detection artifacts
- [ ] SIEM-oriented event output
- [ ] Improved ATT&CK mapping
- [ ] OSINT enrichment
- [ ] Interactive reporting/dashboard
- [ ] Additional reconnaissance engines

These features are intentionally outside the scope of the initial v1 release.

---

# ⚠️ Responsible Use

PurpleRecon is intended for:

- Cybersecurity education
- Authorized laboratories
- CTF environments
- Defensive security research
- Systems and networks you own or have explicit permission to test

Do not use PurpleRecon to scan or analyze systems without authorization.

---

# 🟣 Final Concept

```text
               What can be discovered?
                        │
                        ▼
                  🔴 RED VIEW
                        │
                   Reconnaissance
                        │
                        ▼
                    PurpleRecon
                        ▲
                        │
                   Detection
                        │
                  🔵 BLUE VIEW
                        ▲
                        │
                What can be observed?
```

<p align="center">
  <strong>One workflow. Two perspectives. PurpleRecon.</strong>
</p>
