from sqlalchemy.orm import Session
from app.models import Packet


class PacketService:

    @staticmethod
    def save_packet(db: Session, packet_data: dict):

        packet = Packet(
            source_ip=packet_data["source_ip"],
            destination_ip=packet_data["destination_ip"],
            protocol=packet_data["protocol"],
            source_port=packet_data["source_port"],
            destination_port=packet_data["destination_port"],
            packet_length=packet_data["packet_length"],
            timestamp=packet_data["timestamp"]
        )

        db.add(packet)

        db.commit()

        db.refresh(packet)

        return packet