from app.detection.rules import build_packet_rule
from app.ai_engine.predict import analyze_packet

def detect(packet):
    if not packet:
        return None

    # 1. Rule-based detection
    alert = build_packet_rule(packet)
    if alert:
        return alert

    # 2. AI Anomaly detection
    try:
        is_anomaly = analyze_packet(packet)
        if is_anomaly:
            return {
                "source_ip": packet.get("source_ip"),
                "destination_ip": packet.get("destination_ip"),
                "attack_type": "AI Anomaly Detected",
                "severity": "HIGH",
                "description": "Unusual packet behavior detected by Isolation Forest AI model."
            }
    except Exception as e:
        print(f"AI detection failed: {e}")

    return None