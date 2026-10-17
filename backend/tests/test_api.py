import os, tempfile
os.environ["DATABASE_URL"] = f"sqlite:///{tempfile.mkdtemp()}/test.db"
os.environ["SECRET_KEY"] = "test-secret"
from fastapi.testclient import TestClient
from app.main import app
from app.url_analysis import extract_features, validate_url, heuristic_scan
import pytest

def auth(c, name):
    c.post("/api/v1/auth/register", json={"username": name, "password": "password123"})
    t = c.post("/api/v1/auth/login", json={"username": name, "password": "password123"}).json()["access_token"]
    return {"Authorization": f"Bearer {t}"}

def test_features_and_validation():
    f = extract_features("http://192.168.1.5/login")
    assert f["is_ip_host"] and not f["is_https"]
    with pytest.raises(ValueError): validate_url("ftp://x.com")

def test_heuristic_risk_ordering():
    assert heuristic_scan("https://example.com")["category"] == "Low"
    assert heuristic_scan("http://192.168.1.5/secure-login@verify")["score"] >= 60

def test_flow_and_isolation():
    with TestClient(app) as c:
        assert c.get("/api/v1/scans").status_code == 401
        a, b = auth(c, "alice"), auth(c, "bob")
        r = c.post("/api/v1/scans/url", json={"url": "http://bit.ly/verify-account"}, headers=a)
        assert r.status_code == 201 and ("heuristic" in r.json()["mode"] or "trained ML model" in r.json()["mode"])
        sid = r.json()["id"]
        assert c.get(f"/api/v1/scans/{sid}", headers=a).status_code == 200
        assert c.get(f"/api/v1/scans/{sid}", headers=b).status_code == 404
        assert c.get("/api/v1/scans", headers=b).json()["total"] == 0
        assert c.get("/api/v1/dashboard", headers=a).json()["total"] == 1
        assert "bit.ly" in c.get("/api/v1/scans/export.csv", headers=a).text
        assert c.post("/api/v1/scans/url", json={"url": "nope"}, headers=a).status_code == 422
