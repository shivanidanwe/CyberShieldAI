"""End-to-end API tests for the CyberShield backend."""


def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_home(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "operational"


def test_register_and_login(client):
    register = client.post(
        "/api/auth/register",
        json={"username": "analyst1", "email": "analyst1@example.com", "password": "secret123", "role": "analyst"},
    )
    assert register.status_code == 200
    assert register.json()["username"] == "analyst1"

    login = client.post("/api/auth/login", json={"username": "analyst1", "password": "secret123"})
    assert login.status_code == 200
    assert login.json()["message"] == "Login successful"

    bad_login = client.post("/api/auth/login", json={"username": "analyst1", "password": "wrong"})
    assert bad_login.status_code == 401


def test_submit_packet_creates_alert_for_telnet(client):
    response = client.post(
        "/api/packets",
        json={
            "source_ip": "10.0.0.20",
            "destination_ip": "10.0.0.10",
            "protocol": "TCP",
            "source_port": 50000,
            "destination_port": 23,
            "packet_length": 320,
        },
    )
    assert response.status_code == 200
    packet = response.json()
    assert packet["destination_port"] == 23

    alerts = client.get("/api/alerts").json()
    assert any(alert["attack_type"] == "Telnet Access" for alert in alerts)


def test_dashboard_shape(client):
    client.post(
        "/api/packets",
        json={"source_ip": "10.0.0.20", "destination_ip": "10.0.0.10", "protocol": "TCP", "destination_port": 443, "packet_length": 64},
    )
    client.post(
        "/api/alerts",
        json={"source_ip": "10.0.0.20", "destination_ip": "10.0.0.10", "attack_type": "Test Alert", "severity": "MEDIUM"},
    )
    data = client.get("/api/dashboard").json()
    assert data["total_packets"] >= 1
    assert data["total_alerts"] >= 1
    assert "severity_breakdown" in data
    assert "protocol_breakdown" in data
    assert "recent_alerts" in data
    assert len(data["packets_per_day"]) == 7
    assert len(data["alerts_per_day"]) == 7
    assert "top_source_ips" in data
    assert len(data["top_source_ips"]) >= 1


def test_alert_filters_and_delete(client):
    for severity in ("LOW", "MEDIUM", "HIGH"):
        client.post(
            "/api/alerts",
            json={"source_ip": "10.0.0.20", "destination_ip": "10.0.0.10", "attack_type": "Test", "severity": severity},
        )

    high = client.get("/api/alerts", params={"severity": "HIGH"}).json()
    assert len(high) == 1
    assert high[0]["severity"] == "HIGH"

    searched = client.get("/api/alerts", params={"q": "10.0.0.10"}).json()
    assert len(searched) == 3

    alert_id = high[0]["id"]
    deleted = client.delete(f"/api/alerts/{alert_id}")
    assert deleted.status_code == 200
    assert client.get(f"/api/alerts/{alert_id}").status_code == 404

    cleared = client.delete("/api/alerts")
    assert cleared.status_code == 200
    assert cleared.json()["deleted"] == 2


def test_ai_explain_by_alert_id(client):
    alert = client.post(
        "/api/alerts",
        json={"source_ip": "10.0.0.20", "destination_ip": "10.0.0.10", "attack_type": "RDP Access", "severity": "HIGH"},
    ).json()
    explanation = client.post("/api/ai/explain", json={"alert_id": alert["id"]}).json()
    assert explanation["attack_type"] == "RDP Access"
    assert explanation["recommended_actions"]
    assert explanation["confidence"] >= 0.85


def test_ai_assistant_endpoint(client):
    response = client.post("/api/ai/assistant", json={"message": "summarize the overview"})
    assert response.status_code == 200
    body = response.json()
    assert body["provider"] == "local"
    assert body["reply"]


def test_ai_anomaly_scan_endpoint(client):
    for packet in (
        {"source_ip": "10.0.0.20", "destination_ip": "10.0.0.10", "protocol": "TCP", "destination_port": 443, "packet_length": 64},
        {"source_ip": "10.0.0.20", "destination_ip": "10.0.0.10", "protocol": "TCP", "destination_port": 443, "packet_length": 70},
        {"source_ip": "172.16.9.4", "destination_ip": "10.0.0.10", "protocol": "TCP", "destination_port": 6666, "packet_length": 2500},
    ):
        client.post("/api/packets", json=packet)

    scan = client.post("/api/ai/anomaly-scan", json={"limit": 100, "threshold": 0.6, "create_alerts": True})
    assert scan.status_code == 200
    body = scan.json()
    assert body["scanned"] >= 1
    assert "anomalies" in body
    assert "model" in body
    assert body["model"]["type"] == "isolation-forest"


def test_ai_insights(client):
    insights = client.get("/api/ai/insights").json()
    assert insights["result"] == "ok"
    assert insights["insights"]


def test_port_scan_endpoint(client):
    from datetime import datetime, timedelta

    now = datetime.utcnow()
    for i in range(12):
        client.post(
            "/api/packets",
            json={
                "source_ip": "192.168.1.99",
                "destination_ip": "10.0.0.1",
                "protocol": "TCP",
                "destination_port": 3000 + i,
                "packet_length": 60,
                "timestamp": (now - timedelta(seconds=2 * i)).isoformat(),
            },
        )
    scan = client.post("/api/packets/scan", params={"threshold": 5, "create_alerts": True})
    assert scan.status_code == 200
    body = scan.json()
    assert body["port_scans_detected"] >= 1
    assert body["alerts_created"] >= 1


def test_reports_summary_and_csv(client):
    summary = client.get("/api/reports/summary").json()
    assert "total_packets" in summary
    assert "generated_at" in summary

    alerts_csv = client.get("/api/reports/csv/alerts")
    assert "text/csv" in alerts_csv.headers["content-type"]
    assert "attack_type" in alerts_csv.text

    packets_csv = client.get("/api/reports/csv/packets")
    assert "text/csv" in packets_csv.headers["content-type"]
    assert "protocol" in packets_csv.text