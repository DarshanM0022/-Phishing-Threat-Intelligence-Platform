import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_health_check_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["ml_model_loaded"] is True

def test_url_analysis_endpoint_phishing():
    payload = {
        "target": "https://paypal.com.verify-auth.attacker-12.xyz/signin",
        "target_type": "url"
    }
    response = client.post("/api/v1/analyze/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "risk_score" in data
    assert data["risk_score"] > 50.0
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert data["verdict"] == "phishing"
    assert len(data["indicators"]) > 0
    assert len(data["timeline"]) > 0

def test_url_analysis_endpoint_benign():
    payload = {
        "target": "https://github.com/torvalds/linux",
        "target_type": "url"
    }
    response = client.post("/api/v1/analyze/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] <= 30.0
    assert data["risk_level"] in ["SAFE", "LOW"]
    assert data["verdict"] == "legitimate"

def test_email_analysis_endpoint():
    raw_email = """From: "Account Verification Team" <support@service-update-alert.ru>
Reply-To: phish-collector@mail-redirect.xyz
Subject: URGENT: Your banking profile is suspended

Dear User,
Unauthorized activity was detected on your account. 
You must confirm your credentials within 24 hours or face permanent suspension.

Click here to restore: http://192.168.1.50/banking/verify-identity.html
"""
    payload = {
        "raw_email": raw_email,
        "check_embedded_urls": True
    }
    response = client.post("/api/v1/analyze/email", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] > 60.0
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert len(data["indicators"]) >= 2

def test_history_and_stats_endpoints():
    res_stats = client.get("/api/v1/stats")
    assert res_stats.status_code == 200
    stats = res_stats.json()
    assert stats["total_investigations"] >= 1

    res_hist = client.get("/api/v1/history")
    assert res_hist.status_code == 200
    hist = res_hist.json()
    assert len(hist) >= 1
