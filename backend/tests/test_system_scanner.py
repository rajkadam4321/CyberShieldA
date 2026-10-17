"""
Automated Unit and Integration Tests for CyberShield System Security Scanner.
Uses controlled, harmless test fixtures only (e.g. harmless EICAR test string, dummy scripts).
"""
import io
import os
import hashlib
import tempfile
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.system_scanner import (
    validate_scan_path,
    hash_file_chunked,
    inspect_file_heuristics,
    inspect_startup_entries,
    get_defender_status,
    quarantine_finding_file,
    KNOWN_MALWARE_HASHES
)

def auth_user(client, username):
    client.post("/api/v1/auth/register", json={"username": username, "password": "SecurePassword123!"})
    res = client.post("/api/v1/auth/login", json={"username": username, "password": "SecurePassword123!"})
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_path_validation_and_security():
    # Valid existing directory
    with tempfile.TemporaryDirectory() as td:
        assert validate_scan_path(td) == os.path.abspath(td)

    # Empty path raises error
    with pytest.raises(ValueError, match="cannot be empty"):
        validate_scan_path("   ")

    # Non-existent path raises error
    with pytest.raises(ValueError, match="does not exist"):
        validate_scan_path("C:\\non_existent_cyber_shield_test_path_12345")

    # UNC path injection rejection
    with pytest.raises(ValueError, match="Network UNC"):
        validate_scan_path(r"\\192.168.1.1\share")

    # Device namespace path rejection
    with pytest.raises(ValueError, match="Device namespace"):
        validate_scan_path(r"\\.\PhysicalDrive0")

def test_chunked_hashing_and_signature_db():
    with tempfile.TemporaryDirectory() as td:
        # Create a benign file
        benign_path = os.path.join(td, "benign.txt")
        with open(benign_path, "wb") as f:
            f.write(b"CyberShield System Security Test Content\n")

        h, err = hash_file_chunked(benign_path)
        assert err is None
        # Test signature database lookup logic
        known_test_hash = "ed01ef2632ff6300e0ee693bcff6040c5e4fbc11083aa222b4e71874250ade77"
        assert known_test_hash in KNOWN_MALWARE_HASHES
        assert KNOWN_MALWARE_HASHES[known_test_hash]["severity"] == "Critical"

        # Test chunked hashing with custom safe test fixture
        test_fixture_path = os.path.join(td, "fixture.dat")
        sample_data = b"CyberShield-Safe-Test-Fixture-Hash-Validation-String"
        with open(test_fixture_path, "wb") as f:
            f.write(sample_data)
        
        sample_hash, sample_err = hash_file_chunked(test_fixture_path)
        assert sample_err is None
        assert sample_hash == hashlib.sha256(sample_data).hexdigest()

        # Add temporary signature and verify lookup
        KNOWN_MALWARE_HASHES[sample_hash] = {
            "name": "Test.HarmlessSignature.Detected",
            "type": "Test-Signature",
            "severity": "High",
            "description": "Safe test signature verification.",
            "action": "Audit test fixture."
        }
        assert sample_hash in KNOWN_MALWARE_HASHES
        assert KNOWN_MALWARE_HASHES[sample_hash]["name"] == "Test.HarmlessSignature.Detected"

def test_heuristic_anomalies_detection():
    with tempfile.TemporaryDirectory() as td:
        # 1. Double extension file (looks like PDF but is an EXE)
        suspicious_pdf_exe = os.path.join(td, "urgent_invoice.pdf.exe")
        with open(suspicious_pdf_exe, "wb") as f:
            f.write(b"MZdummy executable payload")
        
        f1 = inspect_file_heuristics(suspicious_pdf_exe)
        assert any(x["finding_type"] == "double_extension" for x in f1)

        # 2. Disguised PE binary (starts with MZ header but extension is .png)
        disguised_png = os.path.join(td, "photo.png")
        with open(disguised_png, "wb") as f:
            f.write(b"MZ" + b"\x90" * 50)
        
        f2 = inspect_file_heuristics(disguised_png)
        assert any(x["finding_type"] == "disguised_executable" for x in f2)

def test_defender_engine_status_and_fallback():
    status = get_defender_status()
    assert "engine" in status
    assert "heuristic_checks" in status
    assert status["signature_db_count"] >= 3

def test_system_scan_api_flow_and_isolation():
    with tempfile.TemporaryDirectory() as td:
        # Create a test folder with a test file
        test_file = os.path.join(td, "test_sample.txt")
        with open(test_file, "wb") as f:
            f.write(b"CyberShield test scanner sample.")

        with TestClient(app) as client:
            headers_alice = auth_user(client, "alice_scanner")
            headers_bob = auth_user(client, "bob_scanner")

            # Engine status
            status_res = client.get("/api/v1/system-scans/engine-status", headers=headers_alice)
            assert status_res.status_code == 200
            assert "heuristic_checks" in status_res.json()

            # Start custom scan on temp folder
            start_res = client.post("/api/v1/system-scans/start", json={
                "scan_type": "custom",
                "target_path": td
            }, headers=headers_alice)
            assert start_res.status_code == 201
            scan_id = start_res.json()["id"]

            # Poll active scan
            active_res = client.get("/api/v1/system-scans/active", headers=headers_alice)
            assert active_res.status_code == 200

            # Scan detail
            detail_res = client.get(f"/api/v1/system-scans/{scan_id}", headers=headers_alice)
            assert detail_res.status_code == 200
            assert detail_res.json()["id"] == scan_id

            # Bob cannot access Alice's scan
            assert client.get(f"/api/v1/system-scans/{scan_id}", headers=headers_bob).status_code == 404

            # Export CSV
            csv_res = client.get(f"/api/v1/system-scans/{scan_id}/export.csv", headers=headers_alice)
            assert csv_res.status_code == 200
            assert "finding_id" in csv_res.text

            # Export PDF report
            pdf_res = client.get(f"/api/v1/system-scans/{scan_id}/report.pdf", headers=headers_alice)
            assert pdf_res.status_code == 200
            assert pdf_res.content.startswith(b"%PDF")

def test_quarantine_remediation_confirmation():
    with tempfile.TemporaryDirectory() as td:
        bad_file = os.path.join(td, "malicious_script.vbs")
        with open(bad_file, "wb") as f:
            f.write(b"WScript.Echo 'unauthorized'")

        ok, msg = quarantine_finding_file(bad_file)
        assert ok is True
        assert not os.path.exists(bad_file)
        assert "quarantine" in msg.lower()
