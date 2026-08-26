## ⚙️ Current Features

PurpleRecon currently includes:

- Nmap-based reconnaissance
- Service and version detection
- Nmap XML parsing
- Structured JSON output
- Security event generation
- Contextual risk analysis
- MITRE ATT&CK context mapping
- Unified JSON reporting
- HTML security reporting
- YAML-based configuration
- Modular Python architecture
- Unit testing with `pytest`

> PurpleRecon is still under active development. Additional traffic analysis and defensive detection capabilities are planned.

---

## 📁 Project Structure

```text
Purple-Recon/
│
├── purple_recon/
│   │
│   ├── recon/
│   │   ├── __init__.py
│   │   └── nmap.py
│   │
│   ├── parsers/
│   │   ├── __init__.py
│   │   └── nmap_parser.py
│   │
│   ├── generators/
│   │   ├── __init__.py
│   │   └── event_generator.py
│   │
│   ├── analysis/
│   │   ├── __init__.py
│   │   ├── risk_analyzer.py
│   │   └── attack_mapper.py
│   │
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── report_builder.py
│   │   └── html_report.py
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
│   ├── test_event_generator.py
│   ├── test_risk_analyzer.py
│   └── test_attack_mapper.py
│
├── output/
│
├── main.py
├── pytest.ini
├── requirements.txt
├── requirements-dev.txt
├── README.md
├── LICENSE
└── .gitignore
```

---

## 🛠️ Requirements

PurpleRecon currently requires:

- **Python 3.12+**
- **Nmap**
- **PyYAML**

Development and testing additionally use:

- **pytest**

> Nmap is a system dependency and is not installed through `requirements.txt`.

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/CaNSu5806/Purple-Recon.git
cd Purple-Recon
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

### 3. Activate the Virtual Environment

#### Windows PowerShell

```powershell
.\venv\Scripts\Activate.ps1
```

#### Linux / macOS

```bash
source venv/bin/activate
```

### 4. Install Runtime Dependencies

```bash
pip install -r requirements.txt
```

For development and testing:

```bash
pip install -r requirements-dev.txt
```

### 5. Verify Nmap

```bash
nmap --version
```

PurpleRecon expects the `nmap` executable to be available in the system `PATH`.

---

## ▶️ Usage

Run a reconnaissance scan using:

```bash
python main.py scan <target>
```

Example:

```bash
python main.py scan 127.0.0.1
```

PurpleRecon will:

```text
Target
  │
  ▼
Nmap Scan
  │
  ▼
XML Output
  │
  ▼
Nmap Parser
  │
  ├──► Security Events
  │
  ├──► Risk Analysis
  │
  └──► MITRE ATT&CK Context
             │
             ▼
        Unified Report
             │
       ┌─────┴─────┐
       ▼           ▼
     JSON         HTML
```

Generated files are stored under:

```text
output/
```

Depending on the enabled reporting options, PurpleRecon can generate:

```text
scan_<target>_<timestamp>.json
events_<target>_<timestamp>.json
risk_<target>_<timestamp>.json
attack_<target>_<timestamp>.json
report_<target>_<timestamp>.json
report_<target>_<timestamp>.html
```

---

## 🔧 Configuration

PurpleRecon uses:

```text
configs/config.yaml
```

to control scanner and output behavior.

Example:

```yaml
scanner:
  ports: "1-1000"
  version_detection: true
  timeout: 120

output:
  directory: "output"
  save_json: true
  save_html: true
```

### Scanner Options

| Option | Description |
|---|---|
| `ports` | Port range or comma-separated ports scanned by Nmap |
| `version_detection` | Enables or disables Nmap service/version detection |
| `timeout` | Maximum scan execution time in seconds |

This allows scan behavior to be changed without modifying the Python source code.

---

## 🧪 Testing

PurpleRecon uses `pytest` for automated unit testing.

Run all tests from the project root:

```bash
pytest
```

Current tests validate components such as:

- Nmap XML parsing
- Security event generation
- Risk classification
- MITRE ATT&CK context mapping

The testing layer helps ensure that existing functionality continues to work as PurpleRecon evolves.

---

## 📊 Output Layers

PurpleRecon intentionally keeps different types of information separated.

| Output | Purpose |
|---|---|
| `scan` | Structured reconnaissance results |
| `events` | Normalized security observations |
| `risk` | Services requiring additional security review |
| `attack` | MITRE ATT&CK contextual mappings |
| `report` | Unified representation of all analysis layers |
| `HTML report` | Human-readable security report |

An exposed service is **not automatically treated as a vulnerability**.

PurpleRecon separates:

```text
Observation
    ↓
Context
    ↓
Risk Analysis
    ↓
ATT&CK Mapping
    ↓
Reporting
```

to avoid making unsupported security conclusions.

---

## 🗺️ Roadmap

Planned development includes:

- [x] Nmap integration
- [x] XML parsing
- [x] Structured JSON output
- [x] Security event generation
- [x] Contextual risk analysis
- [x] MITRE ATT&CK context mapping
- [x] Unified reporting
- [x] HTML reporting
- [x] YAML configuration
- [x] Unit testing
- [ ] TShark integration
- [ ] PCAP parsing
- [ ] TCP flag analysis
- [ ] Scan-pattern detection
- [ ] Network artifact correlation
- [ ] IDS/SIEM-oriented detection mapping
- [ ] Extended CLI options
- [ ] Enhanced HTML dashboard
- [ ] OSINT enrichment

---

```text
[!] Mission     : Purple-Team Reconnaissance Automation
[!] Stage       : Heavy Development & Bug Hunting 🐛
[!] Target ETA  : Soon™
```
