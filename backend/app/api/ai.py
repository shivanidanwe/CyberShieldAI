from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert, Packet
from app.services.ai_service import AnomalyDetector, assistant_respond, build_soc_context, explain_alert
from app.services.alert_service import AlertService
from app.services.packet_service import PacketService

router = APIRouter(tags=["ai"])


class ExplainRequest(BaseModel):
    alert_id: Optional[int] = None
    attack_type: Optional[str] = None
    severity: Optional[str] = "MEDIUM"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    description: Optional[str] = None
    timestamp: Optional[str] = None


class AnomalyScanRequest(BaseModel):
    limit: int = Field(500, ge=10, le=5000)
    threshold: float = Field(0.62, ge=0.0, le=1.0)
    create_alerts: bool = False


class AssistantRequest(BaseModel):
    message: str


class InsightsItem(BaseModel):
    label: str
    value: Any


@router.post("/anomaly-scan")
def anomaly_scan(payload: AnomalyScanRequest, db: Session = Depends(get_db)):
    """Run AI anomaly detection over recent packets and optionally raise alerts."""
    packets_rows = (
        db.query(Packet)
        .order_by(Packet.timestamp.desc())
        .limit(payload.limit)
        .all()
    )
    packets = [
        {
            "id": p.id,
            "source_ip": p.source_ip,
            "destination_ip": p.destination_ip,
            "protocol": p.protocol,
            "source_port": p.source_port,
            "destination_port": p.destination_port,
            "packet_length": p.packet_length,
            "timestamp": (p.timestamp.isoformat() + "Z" if p.timestamp.tzinfo is None else p.timestamp.isoformat()) if p.timestamp else None,
        }
        for p in packets_rows
    ]

    detector = AnomalyDetector()
    result = detector.scan(packets, threshold=payload.threshold, limit=50)

    if payload.create_alerts:
        created = 0
        for anomaly in result["anomalies"]:
            severity = "MEDIUM" if anomaly["score"] < 0.7 else "HIGH"
            AlertService.create_alert(
                db,
                {
                    "source_ip": anomaly["source_ip"],
                    "destination_ip": anomaly["destination_ip"],
                    "attack_type": "AI Anomaly",
                    "severity": severity,
                    "description": anomaly["reason"],
                },
            )
            created += 1
        result["alerts_created"] = created

    result["model"] = {"type": "isolation-forest", "offline": True}
    return result


@router.post("/explain")
def ai_explain(payload: ExplainRequest, db: Session = Depends(get_db)):
    """Explain an alert by id, or an inline alert description."""
    alert_data: Dict[str, Any] = {}
    if payload.alert_id is not None:
        alert = db.query(Alert).filter(Alert.id == payload.alert_id).first()
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        alert_data = {
            "id": alert.id,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "attack_type": alert.attack_type,
            "severity": alert.severity,
            "description": alert.description,
            "timestamp": (alert.timestamp.isoformat() + "Z" if alert.timestamp.tzinfo is None else alert.timestamp.isoformat()) if alert.timestamp else None,
        }
    else:
        if not payload.attack_type:
            raise HTTPException(status_code=400, detail="Provide alert_id or attack_type")
        alert_data = {
            "source_ip": payload.source_ip,
            "destination_ip": payload.destination_ip,
            "attack_type": payload.attack_type,
            "severity": payload.severity,
            "description": payload.description,
            "timestamp": payload.timestamp,
        }

    return explain_alert(alert_data)


@router.post("/assistant")
def ai_assistant(payload: AssistantRequest):
    """Ask the SOC assistant anything about the current posture."""
    context = build_soc_context()
    return assistant_respond(payload.message, context)


@router.get("/insights")
def ai_insights(db: Session = Depends(get_db)):
    context = build_soc_context()
    stats = context.get("stats", {})
    recent = context.get("recent_alerts", [])

    insights: List[InsightsItem] = []

    total_alerts = stats.get("total_alerts", 0)
    high = sum(
        count
        for severity, count in stats.get("severity_breakdown", {}).items()
        if str(severity).upper() in ("HIGH", "CRITICAL")
    )
    posture = "CRITICAL" if high >= 5 else ("ELEVATED" if high >= 1 else "STABLE")
    insights.append(InsightsItem(label="Threat posture", value=posture))
    insights.append(InsightsItem(label="Anomaly activity", value=f"{total_alerts} alert(s), {high} high/critical"))
    insights.append(InsightsItem(label="Top source", value=_insight_top_source(recent)))
    insights.append(InsightsItem(label="Most targeted port", value=_insight_top_port(recent)))

    return {"result": "ok", "insights": [i.model_dump() for i in insights]}


def _insight_top_source(recent: List[Dict[str, Any]]) -> str:
    sources: Dict[str, int] = {}
    for alert in recent:
        source = alert.get("source_ip") or "unknown"
        sources[source] = sources.get(source, 0) + 1
    if not sources:
        return "no data yet"
    top, count = max(sources.items(), key=lambda kv: kv[1])
    return f"{top} ({count} alerts)"


def _insight_top_port(recent: List[Dict[str, Any]]) -> str:
    hints = {
        "telnet": 23,
        "ftp": 21,
        "ssh": 22,
        "rdp": 3389,
        "smb": 445,
        "remote desktop": 3389,
    }
    counts: Dict[str, int] = {}
    for alert in recent:
        attack = (alert.get("attack_type") or "").lower()
        label = "general"
        for key, port in hints.items():
            if key in attack:
                label = f"port {port} ({key})"
                break
        counts[label] = counts.get(label, 0) + 1
    if not counts:
        return "no data yet"
    top, count = max(counts.items(), key=lambda kv: kv[1])
    return f"{top} — {count} alert(s)"