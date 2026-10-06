# CyberShield AI — Project Description

## Project Title
**CyberShield AI: Mini AI-Powered Security Operations Center (SOC)**

## Overview
CyberShield AI is a complete, defensive cybersecurity monitoring platform designed as a final-year academic and production-ready mini-SOC. The platform captures network traffic metadata, stores structured flows in a persistent database, applies deterministic detection rules, runs machine learning anomaly detection, generates security alerts, exposes a high-performance REST API, and visualizes live telemetry on an interactive React SOC dashboard.

---

## Current Status: Fully Implemented & Operational
All planned stages (Milestones 1 through 10) have been engineered, integrated, and validated:

- **FastAPI Backend**: Modular routers for Authentication, Live Packets, Alerts, SOC Dashboard Analytics, AI Intelligence, and Security Reports.
- **Dual-Database Architecture**: Production PostgreSQL support (`cybershield_soc`) with zero-config SQLite local development fallback (`cybershield.db`).
- **Network Metadata Ingestion**: Non-promiscuous and thread-safe Scapy packet sniffing with protocol normalization (TCP, UDP, ICMP).
- **Hybrid Detection Engine**:
  1. *Rule-Based Engine*: Flags unauthorized administrative ports (Telnet 23, FTP 21, SSH 22, RDP 3389, SMB 445), abnormal packet sizing, and sliding-window Port Scans.
  2. *AI Anomaly Engine*: Dual-tier Isolation Forest implementation with statistical baseline profiling (`baseline.json`) that flags statistically rare features and anomalous volume.
- **Explainable AI & SOC Assistant**: Generates human-readable attack summaries, attacker intent analyses, and recommended defensive actions, alongside an interactive natural-language SOC query assistant.
- **Executive Security Reports**: Dynamic on-demand CSV audit logs and professional PDF summary reports powered by ReportLab.
- **React SOC Dashboard**: Modern dark-mode interface featuring real-time overview metrics, alert triage table, live network packet stream, AI analytics scanner, security assistant console, and system settings.
- **Testing & Tooling**: 27/27 passing automated Pytest unit and integration tests, alongside automated start/stop scripts (`start_project.ps1`, `stop_project.ps1`) and synthetic packet simulator (`backend/test_packet.py`).

---

## Core Purpose
CyberShield AI replaces laborious manual packet inspection with an automated, intelligent SOC pipeline. It normalizes network metadata, correlates threats across time windows, surfaces high-priority alerts with actionable remediations, and offers educational clarity for defensive security monitoring.

---

## Target Users
- **Cybersecurity Students**: Hands-on exploration of network telemetry, intrusion detection signatures, and SOC triage workflows.
- **Junior SOC Analysts**: Experience realistic alert categorization, MITRE-aligned explanation cards, and remediation workflows.
- **Lab & Small Office Environments**: Turnkey defensive monitoring for internal subnets and educational ranges.
- **Security Instructors**: Reproducible sandbox for demonstrating reconnaissance, floods, and unauthorized protocol usage.

---

## Core Modules & Architecture

```text
       Authorized Network Traffic
                   |
                   v
         Scapy Packet Capture
                   |
                   v
             Packet Parser
                   |
                   v
         FastAPI Service Layer
                   |
                   v
          SQLAlchemy Models
          (PostgreSQL / SQLite)
                   |
         +---------+---------+
         |                   |
         v                   v
   Packet Storage     Detection Engine
         |                   |
         |         +---------+---------+
         |         |                   |
         |         v                   v
         |    Rule Signatures     AI Anomaly Detector
         |         |                   |
         +---------+---------+---------+
                             |
                             v
                       Alert Service
                             |
                             v
                      FastAPI Endpoints
              (/auth, /packets, /alerts, /ai)
                             |
                   +---------+---------+
                   |                   |
                   v                   v
           PDF / CSV Reports     React SOC Dashboard
```

1. **Packet Capture (`backend/app/packet_capture/`)**:
   - Captures authorized packets via `scapy.all.sniff`.
   - Normalizes IP headers, protocol mappings, transport ports, and packet byte counts.
2. **Persistence (`backend/app/services/packet_service.py`, `alert_service.py`)**:
   - Commits records to `packets` and `alerts` tables with transactional reliability.
3. **Detection Engine (`backend/app/detection/`)**:
   - `rules.py`: Instant signature matches for insecure protocols and sliding-window port scans.
   - `detection_engine.py`: Orchestrates deterministic rules with the AI Anomaly layer.
4. **AI Intelligence (`backend/app/ai_engine/`, `backend/app/services/ai_service.py`)**:
   - `train.py`: Extracts features and builds learned baseline profiles (`baseline.json`).
   - `predict.py`: Evaluates live packets against the trained baseline and Isolation Forest trees.
   - `ai_service.py`: Generates structured alert explanations and interactive SOC Q&A.
5. **Reporting Service (`backend/app/api/reports.py`)**:
   - Streams CSV exports for forensic audits.
   - Generates formatted PDF executive reports using ReportLab.
6. **Frontend Dashboard (`frontend/src/`)**:
   - Built on Vite + React 18 with custom glassmorphism cyber-aesthetic CSS.
   - Live network traffic table with pause/resume and rate controls.
   - Alert management console with severity filtering and AI Explanation modal.
   - Anomaly Scanner panel with configurable score thresholds.
   - Security Assistant interactive chat interface.

---

## Technology Stack
- **Frontend**: React 18, Vite, Vanilla CSS design tokens (responsive dark mode SOC theme)
- **Backend API**: FastAPI, Uvicorn, Pydantic v2
- **Database & ORM**: SQLAlchemy 2.0, SQLite (development), PostgreSQL (production)
- **Packet Ingestion**: Scapy 2.7
- **Machine Learning**: Dual-engine Isolation Forest, Pandas, Scikit-learn, learned statistical baseline
- **Reporting**: ReportLab 5.0, CSV
- **Testing**: PyTest, Pytest-AsyncIO, HTTPX

---

## Ethical & Safety Guidelines
CyberShield AI is strictly a defensive, observational security tool. It must only be operated on networks and endpoints where explicit authorization has been granted. In lab and educational contexts, synthetic packet injection (`test_packet.py` or `app.seed`) is recommended.
