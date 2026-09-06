from scapy.all import sniff
from app.packet_capture.packet_parser import parse_packet
from app.detection.detection_engine import detect
from app.services.alert_service import AlertService
from datetime import datetime

from app.database import SessionLocal
from app.packet_capture.packet_service import PacketService
db = SessionLocal()

def packet_callback(packet):

    parsed = {
    "source_ip": "192.168.1.10",
    "destination_ip": "192.168.1.100",
    "protocol": "TCP",
    "source_port": 50000,
    "destination_port": 23,
    "packet_length": 64,
    "timestamp": datetime.now()
}

    if parsed:

        PacketService.save_packet(db, parsed)

        alert = detect(parsed)

        if alert:
            AlertService.create_alert(db, alert)
            print(f"🚨 ALERT: {alert['attack_type']}")

        print("Packet Saved")


sniff(prn=packet_callback, store=False)