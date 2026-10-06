from sqlalchemy.orm import Session

from app.models import Packet


class PacketService:
    @staticmethod
    def save_packet(db: Session, packet_data: dict):
        packet = Packet(
            source_ip=packet_data["source_ip"],
            destination_ip=packet_data["destination_ip"],
            protocol=packet_data["protocol"],
            source_port=packet_data.get("source_port"),
            destination_port=packet_data.get("destination_port"),
            packet_length=packet_data["packet_length"],
            timestamp=packet_data.get("timestamp"),
            ttl=packet_data.get("ttl"),
            tcp_flags=packet_data.get("tcp_flags"),
            service=packet_data.get("service"),
            info=packet_data.get("info"),
        )
        db.add(packet)
        db.commit()
        db.refresh(packet)
        return packet

    @staticmethod
    def list_packets(db: Session, limit: int = 100, offset: int = 0):
        return db.query(Packet).order_by(Packet.timestamp.desc()).offset(offset).limit(limit).all()

    @staticmethod
    def get_total_packets(db: Session):
        return db.query(Packet).count()
