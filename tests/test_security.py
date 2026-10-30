"""API-key protection of the Phishing Hunter API."""
import os
import socket
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
socket.setdefaulttimeout(3)


@pytest.fixture
def server(monkeypatch):
    import api_server
    monkeypatch.setattr(api_server, "API_KEY", "user-key-1")
    monkeypatch.setattr(api_server, "ADMIN_KEY", "admin-key-9")
    return api_server.app.test_client()


def test_health_is_public(server):
    assert server.get("/health").status_code == 200


def test_endpoints_require_key(server):
    assert server.get("/model_info").status_code == 401
    assert server.get("/model_info", headers={"X-API-Key": "wrong"}).status_code == 401
    assert server.get("/model_info", headers={"X-API-Key": "user-key-1"}).status_code == 200
    r = server.get("/explain_url", query_string={"url": "http://a.tk/login"},
                   headers={"X-API-Key": "user-key-1"})
    assert r.status_code == 200


def test_admin_endpoints_need_admin_key(server):
    assert server.get("/learning_stats", headers={"X-API-Key": "user-key-1"}).status_code == 403
    assert server.get("/learning_stats", headers={"X-API-Key": "admin-key-9"}).status_code == 200
    # admin key also works for normal endpoints
    assert server.get("/model_info", headers={"X-API-Key": "admin-key-9"}).status_code == 200


def test_cors_preflight_not_blocked(server):
    r = server.open("/check_url", method="OPTIONS")
    assert r.status_code in (200, 204)


def test_debug_mode_off_by_default():
    import api_server
    assert not api_server.app.debug
