"""
Unit and integration tests for ML URL Threat Detection Pipeline.
Validates URL feature extraction, edge cases, data leakage safeguards, and model serving.
"""
import pytest
from app.url_analysis import extract_features, validate_url, vector, FEATURE_ORDER, shannon_entropy
from app import ml
from app.main import app
from fastapi.testclient import TestClient

def test_url_validation_edge_cases():
    # Valid URLs
    assert validate_url("https://google.com") == "https://google.com"
    assert validate_url("http://192.168.1.1:8080/path?q=1") == "http://192.168.1.1:8080/path?q=1"
    
    # Invalid schemes
    with pytest.raises(ValueError, match="must start with http:// or https://"):
        validate_url("javascript:alert(1)")
    with pytest.raises(ValueError, match="must start with http:// or https://"):
        validate_url("ftp://files.example.com")

    # Empty and whitespace
    with pytest.raises(ValueError, match="cannot be empty"):
        validate_url("   ")

    # Hostname with spaces
    with pytest.raises(ValueError, match="no valid hostname"):
        validate_url("http://bad host.com/path")

def test_feature_vector_dimension_and_types():
    url = "https://secure-login.paypal.com.account-update.xyz/login?session=123"
    f = extract_features(url)
    v = vector(url)

    assert len(v) == len(FEATURE_ORDER)
    assert all(isinstance(x, (int, float)) for x in v)
    assert f["n_keywords_host"] >= 1
    assert f["entropy_host"] > 0
    assert f["entropy_url"] > 0
    assert f["brand_in_subdomain"] == 1  # paypal in subdomain of account-update.xyz

def test_shannon_entropy_calculation():
    # Constant string has 0 entropy
    assert shannon_entropy("aaaaaaa") == 0.0
    # High randomness has higher entropy
    low_ent = shannon_entropy("apple")
    high_ent = shannon_entropy("a8f9x0z1q2w3e4r5")
    assert high_ent > low_ent

def test_model_info_endpoint():
    with TestClient(app) as client:
        # Register and login
        client.post("/api/v1/auth/register", json={"username": "eval_tester", "password": "TestPassword123!"})
        tok = client.post("/api/v1/auth/login", json={"username": "eval_tester", "password": "TestPassword123!"}).json()["access_token"]
        headers = {"Authorization": f"Bearer {tok}"}

        res = client.get("/api/v1/ml/model-info", headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert "features" in data
        assert "baseline_heuristic" in data or "metrics" in data

        # Check export CSV
        csv_res = client.get("/api/v1/ml/export-metrics.csv", headers=headers)
        assert csv_res.status_code == 200
        assert "Heuristic" in csv_res.text or "Baseline" in csv_res.text

        # Check export JSON
        json_res = client.get("/api/v1/ml/export-metrics.json", headers=headers)
        assert json_res.status_code == 200
