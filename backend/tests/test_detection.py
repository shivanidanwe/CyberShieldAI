"""Unit tests for the rule-based detection engine."""

import pytest

from app.detection.rules import build_packet_rule, detect_port_scan


class TestBuildPacketRule:
    def test_telnet_port_high(self):
        alert = build_packet_rule(
            {"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "destination_port": 23, "packet_length": 200, "protocol": "TCP"}
        )
        assert alert["attack_type"] == "Telnet Access"
        assert alert["severity"] == "HIGH"

    def test_ssh_port_low(self):
        alert = build_packet_rule(
            {"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "destination_port": 22, "packet_length": 200, "protocol": "TCP"}
        )
        assert alert["attack_type"] == "SSH Access"
        assert alert["severity"] == "LOW"

    def test_large_icmp_flood(self):
        alert = build_packet_rule(
            {"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "destination_port": None, "packet_length": 900, "protocol": "ICMP"}
        )
        assert alert["attack_type"] == "ICMP Flood"
        assert alert["severity"] == "HIGH"

    def test_large_packet_medium(self):
        alert = build_packet_rule(
            {"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "destination_port": 5000, "packet_length": 1600, "protocol": "TCP"}
        )
        assert alert["attack_type"] == "Large Packet"
        assert alert["severity"] == "MEDIUM"

    def test_benign_packet_no_alert(self):
        alert = build_packet_rule(
            {"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "destination_port": 443, "packet_length": 100, "protocol": "TCP"}
        )
        assert alert is None

    def test_missing_packet_returns_none(self):
        assert build_packet_rule(None) is None


class TestDetectPortScan:
    def test_detects_scan_from_single_source(self):
        from datetime import datetime, timedelta

        now = datetime.utcnow()
        packets = [
            {"source_ip": "10.0.0.9", "destination_ip": "10.0.0.1", "destination_port": 80 + i, "timestamp": now + timedelta(seconds=i)}
            for i in range(10)
        ]
        alerts = detect_port_scan(packets, window_seconds=60, threshold=5)
        assert len(alerts) == 1
        assert alerts[0]["attack_type"] == "Port Scan"
        assert alerts[0]["severity"] == "MEDIUM"
        assert alerts[0]["source_ip"] == "10.0.0.9"

    def test_ignores_single_port_usage(self):
        from datetime import datetime, timedelta

        now = datetime.utcnow()
        packets = [
            {"source_ip": "10.0.0.9", "destination_ip": "10.0.0.1", "destination_port": 443, "timestamp": now + timedelta(seconds=i)}
            for i in range(20)
        ]
        assert detect_port_scan(packets, window_seconds=60, threshold=5) == []