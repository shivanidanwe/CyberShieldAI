from datetime import datetime, timedelta
from typing import Any, Dict

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert, Packet

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("", response_model=Dict[str, Any])
def dashboard_overview(db: Session = Depends(get_db)):
    total_packets = db.query(Packet).count()
    total_alerts = db.query(Alert).count()

    recent_alerts = (
        db.query(Alert)
        .order_by(Alert.timestamp.desc())
        .limit(10)
        .all()
    )

    severity_breakdown = {}
    for severity, count in db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all():
        severity_breakdown[severity] = count

    protocol_breakdown = {}
    for protocol, count in db.query(Packet.protocol, func.count(Packet.id)).group_by(Packet.protocol).all():
        protocol_breakdown[protocol] = count

    return {
        "total_packets": total_packets,
        "total_alerts": total_alerts,
        "severity_breakdown": severity_breakdown,
        "protocol_breakdown": protocol_breakdown,
        "recent_alerts": [
            {
                "id": alert.id,
                "source_ip": alert.source_ip,
                "destination_ip": alert.destination_ip,
                "attack_type": alert.attack_type,
                "severity": alert.severity,
                "description": alert.description,
                "timestamp": (alert.timestamp.isoformat() + "Z" if alert.timestamp.tzinfo is None else alert.timestamp.isoformat()) if alert.timestamp else None,
            }
            for alert in recent_alerts
        ],
        "packets_per_day": _series_over_days(db, Packet.timestamp),
        "alerts_per_day": _series_over_days(db, Alert.timestamp),
        "top_source_ips": _top_source_ips(db, limit=5),
    }


def _series_over_days(db: Session, column) -> list[Dict[str, Any]]:
    """Count rows per calendar day for the last 7 days (oldest first)."""
    today = datetime.utcnow().date()
    start = today - timedelta(days=6)

    counts = {
        dt: 0
        for dt in (
            start + timedelta(days=i) for i in range(7)
        )
    }

    rows = (
        db.query(func.date(column), func.count(func.date(column)))
        .filter(column >= datetime.combine(start, datetime.min.time()))
        .group_by(func.date(column))
        .all()
    )
    for day, count in rows:
        try:
            parsed = datetime.strptime(str(day), "%Y-%m-%d").date()
            if parsed in counts:
                counts[parsed] = count
        except ValueError:
            continue

    return [
        {"date": day.isoformat(), "count": counts[day]}
        for day in sorted(counts)
    ]


def _top_source_ips(db: Session, limit: int = 5) -> list[Dict[str, Any]]:
    rows = (
        db.query(Alert.source_ip, func.count(Alert.id).label("count"))
        .group_by(Alert.source_ip)
        .order_by(func.count(Alert.id).desc())
        .limit(limit)
        .all()
    )
    return [{"source_ip": ip, "count": count} for ip, count in rows]


@router.get("/summary")
def summary(db: Session = Depends(get_db)):
    total_packets = db.query(Packet).count()
    total_alerts = db.query(Alert).count()
    severity_counts = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()

    return {
        "total_packets": total_packets,
        "total_alerts": total_alerts,
        "alerts_by_severity": {severity: count for severity, count in severity_counts},
    }