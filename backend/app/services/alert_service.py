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
            description=alert_data["description"]
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        return alert