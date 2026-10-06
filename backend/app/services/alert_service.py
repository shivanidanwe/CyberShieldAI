from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import Alert


class AlertService:
    @staticmethod
    def create_alert(db: Session, alert_data: dict):
        alert = Alert(
            source_ip=alert_data["source_ip"],
            destination_ip=alert_data["destination_ip"],
            attack_type=alert_data["attack_type"],
            severity=alert_data["severity"],
            description=alert_data.get("description"),
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return alert

    @staticmethod
    def list_alerts(db: Session, limit: int = 100, offset: int = 0):
        return db.query(Alert).order_by(Alert.timestamp.desc()).offset(offset).limit(limit).all()

    @staticmethod
    def get_alerts_by_severity(db: Session):
        return (
            db.query(Alert.severity, func.count(Alert.id).label("count"))
            .group_by(Alert.severity)
            .order_by(Alert.severity.asc())
            .all()
        )

    @staticmethod
    def get_total_alerts(db: Session):
        return db.query(Alert).count()