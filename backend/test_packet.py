"""CyberShield AI — Safe End-to-End Simulation & Verification Script.

Tests the packet -> database -> detection -> alert -> AI anomaly pipeline
with synthetic packets without generating any live network traffic.
"""

from datetime import datetime
import sys
import os

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.database import SessionLocal, Base, engine
from app.models import Packet, Alert
from app.services.packet_service import PacketService
from app.services.alert_service import AlertService
from app.detection.detection_engine import detect


def run_simulation():
    print("=" * 65)
    print("[+] CyberShield AI - End-to-End Pipeline Verification")
    print("=" * 65)

    # 1. Initialize schema
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    test_cases = [
        {
            "name": "Benign HTTPS Web Traffic",
            "packet": {
                "source_ip": "192.168.1.15",
                "destination_ip": "142.250.190.46",
                "protocol": "TCP",
                "source_port": 54321,
                "destination_port": 443,
                "packet_length": 128,
                "timestamp": datetime.utcnow(),
            },
            "expect_alert": False,
        },
        {
            "name": "Suspicious Telnet Access (Port 23)",
            "packet": {
                "source_ip": "192.168.1.10",
                "destination_ip": "192.168.1.100",
                "protocol": "TCP",
                "source_port": 50000,
                "destination_port": 23,
                "packet_length": 64,
                "timestamp": datetime.utcnow(),
            },
            "expect_alert": True,
            "expected_attack": "Telnet Access",
        },
        {
            "name": "Abnormal ICMP Flood Volume",
            "packet": {
                "source_ip": "10.0.0.99",
                "destination_ip": "10.0.0.1",
                "protocol": "ICMP",
                "source_port": None,
                "destination_port": None,
                "packet_length": 1200,
                "timestamp": datetime.utcnow(),
            },
            "expect_alert": True,
            "expected_attack": "ICMP Flood",
        },
        {
            "name": "AI Anomaly (High Statistical Deviation)",
            "packet": {
                "source_ip": "172.16.0.44",
                "destination_ip": "172.16.0.1",
                "protocol": "TCP",
                "source_port": 61234,
                "destination_port": 9999,
                "packet_length": 1150,
                "timestamp": datetime.utcnow(),
            },
            "expect_alert": True,
            "expected_attack": "AI Anomaly Detected",
        },
    ]

    passed = 0
    for idx, tc in enumerate(test_cases, 1):
        p_data = tc["packet"]
        print(f"\n[Test {idx}/4] {tc['name']} ...")

        # Step 1: Save packet
        saved_pkt = PacketService.save_packet(db, p_data)
        print(f"  [OK] Packet saved to DB (ID: {saved_pkt.id})")

        # Step 2: Run detection engine
        alert_data = detect(p_data)

        if tc["expect_alert"]:
            if alert_data:
                # Step 3: Create alert
                created_alert = AlertService.create_alert(db, alert_data)
                print(f"  [ALERT TRIGGERED] {alert_data['attack_type']} [{alert_data['severity']}]")
                print(f"    Alert ID: {created_alert.id} | Description: {alert_data['description']}")
                passed += 1
            else:
                print(f"  [FAIL] Expected alert for {tc['name']}, but none was triggered.")
        else:
            if alert_data is None:
                print("  [OK] Benign packet passed without alerts.")
                passed += 1
            else:
                print(f"  [FAIL] Unexpected alert triggered: {alert_data}")


    db.close()

    print("\n" + "=" * 65)
    print(f"Results: {passed}/{len(test_cases)} tests passed successfully!")
    print("=" * 65)
    return passed == len(test_cases)


if __name__ == "__main__":
    success = run_simulation()
    sys.exit(0 if success else 1)