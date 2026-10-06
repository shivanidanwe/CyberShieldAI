"""Tests for the dependency-free AI layer."""

from app.services.ai_service import AnomalyDetector, explain_alert, assistant_respond


def test_anomaly_detector_scores_packets():
    detector = AnomalyDetector(n_estimators=16, max_depth=8, sample_size=32)
    packets = [
        {"source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "protocol": "TCP", "destination_port": 443, "packet_length": 100},
        {"source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "protocol": "TCP", "destination_port": 443, "packet_length": 110},
        {"source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "protocol": "TCP", "destination_port": 443, "packet_length": 95},
        {"source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "protocol": "TCP", "destination_port": 443, "packet_length": 4000},
        {"source_ip": "10.0.0.3", "destination_ip": "10.0.0.2", "protocol": "ICMP", "destination_port": None, "packet_length": 1400},
    ]
    scored = detector.score(packets)
    assert len(scored) == len(packets)
    # The oversized outlier should score higher than the typical cluster.
    typical = [p["score"] for p in scored if p["packet_length"] < 200]
    outlier = [p["score"] for p in scored if p["packet_length"] == 4000][0]
    assert outlier > max(typical)


def test_scan_reports_outliers():
    detector = AnomalyDetector(n_estimators=16, max_depth=8, sample_size=32)
    packets = [
        {"source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "protocol": "TCP", "destination_port": 443, "packet_length": 100},
        {"source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "protocol": "UDP", "destination_port": 53, "packet_length": 120},
        {"source_ip": "10.0.0.5", "destination_ip": "10.0.0.2", "protocol": "TCP", "destination_port": 6666, "packet_length": 2500},
    ]
    result = detector.scan(packets, threshold=0.6)
    assert result["scanned"] == 3
    assert isinstance(result["anomalies"], list)
    for anomaly in result["anomalies"]:
        assert "score" in anomaly
        assert "reason" in anomaly
        assert "recommendation" in anomaly


def test_scan_empty_inputs():
    detector = AnomalyDetector()
    result = detector.scan([])
    assert result["scanned"] == 0
    assert result["anomalies"] == []


def test_explain_alert_known_attack():
    explanation = explain_alert(
        {
            "id": 1,
            "source_ip": "10.0.0.9",
            "destination_ip": "10.0.0.10",
            "attack_type": "Telnet Access",
            "severity": "HIGH",
            "description": "Traffic matched a suspicious service on port 23.",
        }
    )
    assert explanation["attack_type"] == "Telnet Access"
    assert explanation["severity"] == "HIGH"
    assert explanation["confidence"] >= 0.85
    assert "Telnet" in explanation["summary"]
    assert explanation["recommended_actions"]
    assert explanation["why_flagged"]


def test_explain_alert_unknown_falls_back():
    explanation = explain_alert({"attack_type": "Weird Custom Event", "severity": "MEDIUM"})
    assert explanation["attack_type"] == "Weird Custom Event"
    assert explanation["recommended_actions"]


def test_assistant_responds_overview():
    from datetime import datetime, timedelta

    context = {
        "stats": {
            "total_packets": 1000,
            "total_alerts": 12,
            "severity_breakdown": {"HIGH": 2, "MEDIUM": 5, "LOW": 5},
            "protocol_breakdown": {"TCP": 800, "UDP": 150, "ICMP": 50},
        },
        "recent_alerts": [
            {
                "id": 1,
                "source_ip": "10.0.0.9",
                "destination_ip": "10.0.0.10",
                "attack_type": "Telnet Access",
                "severity": "HIGH",
                "timestamp": "2026-09-06T12:00:00",
            }
        ],
        "top_sources": [["10.0.0.9", 3]],
    }
    reply = assistant_respond("what is the overview?", context)
    assert "provider" in reply
    assert reply["provider"] == "local"
    assert "1000 packets" in reply["reply"]
    assert "ELEVATED" in reply["reply"]


def test_assistant_fallback_graceful():
    reply = assistant_respond("zyzz lovelace?", {"stats": {}})
    assert reply["provider"] == "local"
    assert reply["reply"]