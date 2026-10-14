
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health():
    assert client.get("/healthz").json()["status"] == "ok"


def test_ready_is_mock_mode():
    data = client.get("/readyz").json()
    assert data["mode"] == "mock"
    assert data["falcon_connected"] is False


def test_seed_alerts_exist():
    response = client.get("/alerts")
    assert response.status_code == 200
    assert len(response.json()) >= 4


def test_summary():
    data = client.get("/summary").json()
    assert data["total_alerts"] >= 4
    assert "critical" in data["by_severity"]


def test_filter_by_severity():
    response = client.get("/alerts?severity=high")
    assert response.status_code == 200
    assert all(
        alert["severity"] == "high"
        for alert in response.json()
    )


def test_ingest_mock_alert():
    payload = {
        "alert_id": "test-alert-9001",
        "host_name": "test-host",
        "detection_name": "Suspicious PowerShell activity",
        "category": "execution",
        "source": "mock",
        "tags": ["workstation"],
    }

    response = client.post("/alerts", json=payload)
    assert response.status_code == 201
    assert response.json()["risk_score"] > 0


def test_duplicate_alert_rejected():
    payload = {
        "alert_id": "duplicate-test-1",
        "host_name": "test-host",
        "detection_name": "Test detection",
        "category": "test",
        "source": "mock",
    }

    assert client.post("/alerts", json=payload).status_code == 201
    assert client.post("/alerts", json=payload).status_code == 409


def test_live_source_is_not_faked():
    payload = {
        "alert_id": "live-test-1",
        "host_name": "test-host",
        "detection_name": "Test detection",
        "category": "test",
        "source": "crowdstrike",
    }

    assert client.post("/alerts", json=payload).status_code == 501


def test_metrics():
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "devsecops_alerts_total" in response.text
