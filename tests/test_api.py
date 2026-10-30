"""API smoke tests (no network needed; email model optional)."""
import os
import socket
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
socket.setdefaulttimeout(3)


@pytest.fixture(scope="module")
def client():
    import api_server
    return api_server.app.test_client()


def test_health(client):
    body = client.get("/health").get_json()
    assert body["detector_loaded"] is True


def test_explain_url(client):
    r = client.get("/explain_url", query_string={"url": "http://paypal-secure-login.verify-account.tk/webscr"})
    assert r.status_code == 200
    body = r.get_json()
    assert body["prediction"] == "phishing"
    assert body["toward_phishing"]


def test_explain_url_requires_url(client):
    assert client.get("/explain_url").status_code == 400


def test_model_info(client):
    body = client.get("/model_info").get_json()
    assert body["model_type"] == "LogisticRegression" and body["f1"] > 0.9


def test_email_analysis_falls_back_to_patterns(client):
    r = client.post("/analyze_email", json={
        "sender": "security@paypa1-alerts.tk",
        "subject": "URGENT: account suspended",
        "content": "Your account is suspended. Click here to verify your password immediately.",
    })
    assert r.status_code == 200
