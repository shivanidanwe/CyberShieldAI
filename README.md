# CyberShield AI: Mini AI-Powered Security Operations Center (SOC)

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-cyan.svg)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-5+-purple.svg)](https://vitejs.dev/)
[![Tests Passing](https://img.shields.io/badge/pytest-27%2F27%20passed-brightgreen.svg)]()

**CyberShield AI** is an end-to-end, defensive cybersecurity monitoring platform engineered as a complete final-year academic mini-SOC. The platform captures network traffic metadata, stores structured flows in a persistent database, applies deterministic detection rules, runs machine learning anomaly detection (Isolation Forest), generates security alerts, exposes a high-performance REST API, and visualizes live telemetry on an interactive React SOC dashboard.

---

## 🚀 Key Features

1. **Live Network Ingestion**:
   - Thread-safe Scapy packet sniffing with background worker controls (`capture.py`).
   - Normalization of IP, TCP, UDP, and ICMP protocols.
   - Non-promiscuous, defensive metadata extraction (source/destination IP, ports, lengths, timestamps).

2. **Dual-Tier Detection Engine**:
   - **Signature Rules**: Instant detection of insecure protocols (Telnet `23`, FTP `21`, SSH `22`, RDP `3389`, SMB `445`), oversized MTU payloads, and abnormal ICMP floods.
   - **Sliding-Window Correlation**: Multi-packet port-scan detection identifying reconnaissance behavior across time windows.
   - **AI Anomaly Detection**: Dual-mode Isolation Forest model (`predict.py`) backed by an offline statistical baseline (`baseline.json`) that flags statistically rare features and volume spikes.

3. **Explainable AI & SOC Assistant**:
   - Automated attack analysis providing **Why Flagged**, **Attacker Intent**, and **Recommended Mitigations**.
   - Interactive conversational SOC assistant for querying live network posture, top attackers, and posture ratings.
   - Optional Claude AI API integration when `CYBERSHIELD_ANTHROPIC_API_KEY` is configured.

4. **Executive Security Reports**:
   - Forensic CSV export for packets and alerts.
   - Formatted, executive PDF security summary reports generated on-demand via ReportLab.

5. **Modern React SOC Dashboard**:
   - Real-time posture cards, protocol donut charts, and 7-day incident trend SVG visualizations.
   - Live network packet stream with play/pause and synthetic injection.
   - Comprehensive alert triage table with severity badges and AI explanation modals.
   - AI Anomaly Scanner with interactive confidence threshold tuning.
   - Dark-mode glassmorphic interface built with responsive Vanilla CSS tokens.

---

## 📁 Repository Structure

```text
CyberShieldAI/
├── backend/
│   ├── app/
│   │   ├── ai_engine/           # ML model, feature extraction & training
│   │   │   ├── baseline.json    # Learned traffic statistical baseline
│   │   │   ├── predict.py       # Isolation Forest & baseline inference
│   │   │   └── train.py         # Model training script
│   │   ├── api/                 # Modular FastAPI route controllers
│   │   │   ├── ai.py            # AI scan, assistant & explanation endpoints
│   │   │   ├── alerts.py        # Alert triage & management
│   │   │   ├── auth.py          # User authentication & RBAC
│   │   │   ├── dashboard.py     # Metrics, trends & protocol summaries
│   │   │   ├── packets.py       # Packet ingestion & queries
│   │   │   └── reports.py       # PDF & CSV reporting exports
│   │   ├── detection/           # Rule-based detection & correlation
│   │   │   ├── detection_engine.py # Rule + AI orchestration
│   │   │   └── rules.py         # Signature definitions & port-scan windows
│   │   ├── packet_capture/      # Network capture & normalization
│   │   │   ├── capture.py       # Live Scapy capture loop
│   │   │   └── packet_parser.py # Header & layer parsing
│   │   ├── services/            # Business logic & ORM services
│   │   │   ├── ai_service.py    # Dependency-free Isolation Forest & KB
│   │   │   ├── alert_service.py # Alert persistence & aggregations
│   │   │   └── packet_service.py# Packet storage & pagination
│   │   ├── config.py            # Dual-database configuration
│   │   ├── database.py          # SQLAlchemy engine & session factory
│   │   ├── main.py              # FastAPI application entrypoint
│   │   ├── models.py            # User, Packet, Alert SQLAlchemy models
│   │   ├── schemas.py           # Pydantic request/response schemas
│   │   └── seed.py              # Demo dataset generator (4,900+ flows)
│   ├── tests/                   # Automated Pytest suite
│   │   ├── test_ai.py           # Isolation Forest & AI assistant tests
│   │   ├── test_api.py          # End-to-end REST API endpoint tests
│   │   └── test_detection.py    # Signature rules & scan window tests
│   ├── cybershield.db           # Persistent local SQLite database
│   ├── requirements.txt         # Backend Python dependencies
│   └── test_packet.py           # Interactive end-to-end simulation script
├── frontend/
│   ├── src/
│   │   ├── components/          # Reusable UI components & modals
│   │   ├── pages/               # Overview, Network, Alerts, Analytics, Assistant
│   │   ├── lib/                 # API client & CSV exporter
│   │   ├── App.jsx              # Main router & layout shell
│   │   └── index.css            # Dark mode cyber-aesthetic styling
│   ├── package.json             # Frontend dependencies & scripts
│   └── vite.config.js           # Vite dev server configuration
├── PRD.md                       # Product Requirements Document
├── project_description.md       # Architectural overview & academic scope
├── start_project.ps1            # Single-command startup orchestrator
├── stop_project.ps1             # Clean shutdown script
└── README.md                    # Project documentation
```

---

## ⚡ Quick Start

### 1. One-Click Launch (Windows)

To start both the FastAPI backend (`http://127.0.0.1:8000`) and the React dashboard (`http://localhost:5173`):

```powershell
./start_project.ps1
```

To stop all services cleanly:

```powershell
./stop_project.ps1
```

---

### 2. Manual Launch

#### Backend:
```bash
# 1. Navigate to backend
cd backend

# 2. Start API server
py -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
* Interactive API Documentation: **http://127.0.0.1:8000/docs**

#### Frontend:
```bash
# 1. Navigate to frontend
cd frontend

# 2. Install dependencies (if first time)
npm install

# 3. Launch Vite development server
npm run dev
```
* Dashboard URL: **http://localhost:5173**

---

## 🧪 Testing & Verification

### Run Automated Pytest Suite (27/27 Tests)
```bash
py -m pytest backend/tests
```

### Run Synthetic Pipeline Simulation
To verify the complete packet ingestion -> detection -> alert -> AI anomaly pipeline without generating live network traffic:
```bash
py backend/test_packet.py
```

Expected output:
```
=================================================================
[+] CyberShield AI - End-to-End Pipeline Verification
=================================================================

[Test 1/4] Benign HTTPS Web Traffic ...
  [OK] Packet saved to DB (ID: 4907)
  [OK] Benign packet passed without alerts.

[Test 2/4] Suspicious Telnet Access (Port 23) ...
  [OK] Packet saved to DB (ID: 4908)
  [ALERT TRIGGERED] Telnet Access [HIGH]
    Alert ID: 131 | Description: Traffic matched a suspicious service on port 23.

[Test 3/4] Abnormal ICMP Flood Volume ...
  [OK] Packet saved to DB (ID: 4909)
  [ALERT TRIGGERED] ICMP Flood [HIGH]
    Alert ID: 132 | Description: ICMP traffic exceeded the configured packet-size threshold for abnormal activity.

[Test 4/4] AI Anomaly (High Statistical Deviation) ...
  [OK] Packet saved to DB (ID: 4910)
  [ALERT TRIGGERED] AI Anomaly Detected [HIGH]
    Alert ID: 133 | Description: Unusual packet behavior detected by Isolation Forest AI model.

=================================================================
Results: 4/4 tests passed successfully!
=================================================================
```

### Retrain AI Statistical Baseline
To retrain the Isolation Forest and update `baseline.json` on the database:
```bash
cd backend
py -m app.ai_engine.train
```

---

## 🛡️ Default Demo Credentials
- **Username**: `admin`
- **Password**: `admin123`
*(Pre-seeded with demo telemetry and role: `admin`)*

---

## ⚖️ Safety & Ethical Use
CyberShield AI is built solely for educational, defensive monitoring, and academic research on authorized networks. Do not use this tool on networks without prior written authorization.
