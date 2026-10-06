# Product Requirements Document (PRD)

## Project Title
**CyberShield AI: Mini AI-Powered Security Operations Center (SOC)**

---

## 1. Executive Summary & Problem Statement
Modern enterprise networks encounter thousands of packet transactions every second. Analyzing raw PCAP dumps manually is infeasible for small organizations, lab researchers, and novice SOC analysts. Existing commercial SIEM/SOC platforms (Splunk, Sentinel, QRadar) are complex, resource-heavy, and cost-prohibitive for academic study.

**CyberShield AI** bridges this gap by providing an educational, lightweight, and fully functional mini-SOC. It continuously ingests authorized network flows, structures metadata into relational storage, executes deterministic security rules alongside machine learning anomaly detection, surfaces prioritized alerts, and provides a real-time reactive dashboard with explainable AI recommendations.

---

## 2. Core Target Users
- **Cybersecurity & Networking Students**: Understand OSI layers, transport security, port vulnerabilities, and intrusion signatures.
- **Junior SOC Analysts**: Learn alert triage, triage severity matrices, and MITRE-aligned incident responses.
- **Academic Instructors**: Conduct reproducible demonstrations of reconnaissance attacks (e.g., port scans, ICMP floods).
- **Small Organizations & Labs**: Deploy lightweight, low-footprint defensive monitoring without cloud dependencies.

---

## 3. End-to-End Processing Chain
```text
AUTHORIZED TRAFFIC
        ↓
 SCAPY PACKET CAPTURE
        ↓
   PACKET PARSER
        ↓
   PACKET SERVICE
        ↓
DATABASE STORAGE (PostgreSQL / SQLite)
        ↓
RULE DETECTION + AI ANOMALY ENGINE
        ↓
    ALERT SERVICE
        ↓
   REST API LAYER (FastAPI)
        ↓
 REACT SOC DASHBOARD (Vite)
        ↓
ANALYTICS / REPORTS / AI ASSISTANT
```

---

## 4. Functional Requirements

### 4.1 Ingestion & Normalization
- **FR-1.1**: Thread-safe capture of live network packets using Scapy without dropping administrative control.
- **FR-1.2**: Extract packet metadata: source IP, destination IP, protocol (TCP, UDP, ICMP), transport ports, byte length, and timestamp.
- **FR-1.3**: Fallback to synthetic packet generation for lab simulation without active network scanning.

### 4.2 Storage & Data Persistence
- **FR-2.1**: Relational models for `users`, `packets`, and `alerts` managed through SQLAlchemy 2.0 ORM.
- **FR-2.2**: Seamless support for local development SQLite (`cybershield.db`) and production PostgreSQL (`cybershield_soc`).
- **FR-2.3**: Automatic database seeding with pre-generated 7-day realistic corpus.

### 4.3 Detection Engine
- **FR-3.1 (Signature Rules)**:
  - Telnet (TCP 23) -> HIGH severity alert.
  - FTP (TCP 21) -> MEDIUM severity alert.
  - SSH (TCP 22) -> LOW severity audit alert.
  - Remote Desktop Protocol / RDP (TCP 3389) -> HIGH severity alert.
  - SMB / Windows Sharing (TCP 445) -> MEDIUM severity alert.
- **FR-3.2 (Behavioral Rules)**:
  - Large packet anomaly (>1500 bytes MTU violation).
  - ICMP flood traffic (>800 bytes).
  - Port-scan correlation: ≥8 distinct destination ports touched by the same source IP in a 60-second window.
- **FR-3.3 (AI Anomaly Detection)**:
  - Dual-mode Isolation Forest scoring numeric packet features (`destination_port`, `packet_length`, `protocol`, `source_port`).
  - Pre-computed statistical baseline (`baseline.json`) flagging statistical deviations (Z-score ≥ 2.5).

### 4.4 Explainable AI & Security Assistant
- **FR-4.1**: Automatic alert explanations detailing **Attack Type**, **Why Flagged**, **Attacker Intent**, and **Recommended Mitigations**.
- **FR-4.2**: Conversational SOC assistant answering natural-language inquiries regarding network posture, top attackers, and traffic distribution.
- **FR-4.3**: Optional integration with Claude LLM API via `CYBERSHIELD_ANTHROPIC_API_KEY`.

### 4.5 SOC Dashboard & Reporting
- **FR-5.1**: KPI overview cards displaying total packets, alerts, active capture status, and threat posture.
- **FR-5.2**: Protocol distribution donut chart and 7-day incident trend SVG visualization.
- **FR-5.3**: Live packet stream table with play/pause and injection modal.
- **FR-5.4**: Alert triage view with severity filter chips and modal triage view.
- **FR-5.5**: Export capabilities: forensic CSV data streams and executive PDF security reports (ReportLab).

---

## 5. Non-Functional Requirements
- **NFR-1 (Performance)**: Sub-50ms query response on dashboard metrics; asynchronous live capture loop.
- **NFR-2 (Compatibility)**: Native execution on Windows 10/11 and Linux; offline functionality with zero mandatory external API keys.
- **NFR-3 (Reliability)**: Graceful fallback to pure-Python anomaly detection when OS Application Control policies block binary C-extension DLLs.
- **NFR-4 (Security)**: Password hashing with bcrypt, strict CORS origin policies, and read-only non-promiscuous capture mode.

---

## 6. Verification & Acceptance Criteria
- [x] All 27 Pytest automated unit and integration tests passing.
- [x] Live API operational at `http://127.0.0.1:8000/api/health`.
- [x] React SOC dashboard rendering at `http://localhost:5173`.
- [x] Synthetic injection and live capture triggering expected alerts in SQLite / PostgreSQL.
- [x] Production PDF / CSV export verified.
