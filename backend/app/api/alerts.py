from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert
from app.schemas import AlertCreate, AlertRead
from app.services.alert_service import AlertService

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.post("", response_model=AlertRead)
def create_alert(alert: AlertCreate, db: Session = Depends(get_db)):
    record = AlertService.create_alert(db, alert.model_dump(exclude_none=True))
    return record


@router.get("", response_model=List[AlertRead])
def list_alerts(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW / MEDIUM / HIGH / CRITICAL)"),
    q: Optional[str] = Query(None, description="Search attack type, source or destination IP"),
    db: Session = Depends(get_db),
):
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity.ilike(severity.strip()))
    if q:
        term = f"%{q.strip()}%"
        query = query.filter(
            or_(
                Alert.attack_type.ilike(term),
                Alert.source_ip.ilike(term),
                Alert.destination_ip.ilike(term),
                Alert.description.ilike(term),
            )
        )
    alerts = query.order_by(Alert.timestamp.desc()).offset(offset).limit(limit).all()
    return alerts


@router.get("/{alert_id}", response_model=AlertRead)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.delete("/{alert_id}")
def delete_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    db.delete(alert)
    db.commit()
    return {"result": "ok", "deleted": alert_id}


@router.delete("")
def clear_alerts(db: Session = Depends(get_db)):
    deleted = db.query(Alert).delete()
    db.commit()
    return {"result": "ok", "deleted": deleted}