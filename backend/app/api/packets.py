from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.detection.detection_engine import detect
from app.detection.rules import detect_port_scan
from app.models import Packet
from app.packet_capture.capture import get_capture_status, start_capture, stop_capture
from app.schemas import CaptureToggleRequest, PacketCreate, PacketRead
from app.services.alert_service import AlertService
from app.services.packet_service import PacketService

router = APIRouter(prefix="/packets", tags=["packets"])


@router.post("/scan")
def scan_packets_for_port_scan(
    window_seconds: int = Query(60, ge=10, le=3600),
    threshold: int = Query(8, ge=3, le=100),
    create_alerts: bool = False,
    db: Session = Depends(get_db),
):
    """Correlate stored packets to detect port scans, optionally storing alerts."""
    from datetime import datetime, timedelta

    since = datetime.utcnow() - timedelta(seconds=window_seconds * 2)
    rows = db.query(Packet).filter(Packet.timestamp >= since).all()
    packets = [
        {
            "source_ip": p.source_ip,
            "destination_ip": p.destination_ip,
            "destination_port": p.destination_port,
            "timestamp": p.timestamp,
        }
        for p in rows
    ]

    found = detect_port_scan(packets, window_seconds=window_seconds, threshold=threshold)
    detected = len(found)
    if create_alerts and found:
        for alert in found:
            AlertService.create_alert(db, alert)

    return {
        "result": "ok",
        "scanned": len(packets),
        "port_scans_detected": detected,
        "alerts_created": detected if (create_alerts and found) else 0,
        "port_scans": found,
        "window_seconds": window_seconds,
        "threshold": threshold,
    }


@router.get("/capture/status")
def packet_capture_status():
    return get_capture_status()


@router.post("/capture/toggle")
def toggle_packet_capture(request: CaptureToggleRequest):
    try:
        if request.enabled:
            return start_capture()
        return stop_capture()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("", response_model=PacketRead)
def create_packet(packet: PacketCreate, db: Session = Depends(get_db)):
    packet_data = packet.model_dump(exclude_none=True)
    created = PacketService.save_packet(db, packet_data)

    alert = detect(packet_data)
    if alert:
        AlertService.create_alert(db, alert)

    return created


@router.get("", response_model=List[PacketRead])
def list_packets(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    protocol: Optional[str] = Query(None, description="Filter by protocol (TCP / UDP / ICMP)"),
    db: Session = Depends(get_db),
):
    query = db.query(Packet)
    if protocol:
        query = query.filter(Packet.protocol.ilike(protocol.strip()))
    packets = (
        query.order_by(Packet.timestamp.desc()).offset(offset).limit(limit).all()
    )
    return packets


@router.get("/{packet_id}", response_model=PacketRead)
def get_packet(packet_id: int, db: Session = Depends(get_db)):
    packet = db.query(Packet).filter(Packet.id == packet_id).first()
    if packet is None:
        raise HTTPException(status_code=404, detail="Packet not found")
    return packet
