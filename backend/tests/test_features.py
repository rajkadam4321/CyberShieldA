import io, os, random, tempfile, zipfile
os.environ["DATABASE_URL"] = f"sqlite:///{tempfile.mkdtemp()}/f.db"
import pandas as pd
from fastapi.testclient import TestClient
from app.main import app
from app import ml
from app.file_analysis import analyze
from training.train_model import train

def auth(c, n):
    c.post("/api/v1/auth/register", json={"username": n, "password": "password123"})
    t = c.post("/api/v1/auth/login", json={"username": n, "password": "password123"}).json()["access_token"]
    return {"Authorization": f"Bearer {t}"}

def test_file_checks():
    assert analyze("invoice.pdf.exe", b"MZ\x90\x00")["category"] == "High"
    assert analyze("photo.png", b"MZ\x90")["findings"]
    assert analyze("notes.txt", b"hello")["category"] == "Low"
    assert analyze("../../etc/passwd.txt", b"x")["metadata"]["filename"] == "passwd.txt"

def test_zip_inspection_is_safe():
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z: z.writestr("../evil.txt", "x"); z.writestr("run.exe", "x")
    a = analyze("a.zip", b.getvalue())
    names = [f["indicator"] for f in a["findings"]]
    assert "Path traversal in archive" in names and "Executable inside archive" in names

def test_upload_limits_report_quiz_isolation(monkeypatch):
    with TestClient(app) as c:
        a, b = auth(c, "user1"), auth(c, "user2")
        r = c.post("/api/v1/scans/file", files={"file": ("x.pdf.exe", b"MZ123")}, headers=a)
        assert r.status_code == 201 and r.json()["category"] == "High" and r.json()["metadata"]["sha256"]
        sid = r.json()["id"]
        pdf = c.get(f"/api/v1/scans/{sid}/report.pdf", headers=a)
        assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
        assert c.get(f"/api/v1/scans/{sid}/report.pdf", headers=b).status_code == 404
        assert c.get("/api/v1/dashboard", headers=a).json()["file"] == 1
        monkeypatch.setenv("MAX_UPLOAD_MB", "0")
        assert c.post("/api/v1/scans/file", files={"file": ("a.txt", b"hi")}, headers=a).status_code == 413
        q = c.get("/api/v1/awareness/quiz", headers=a).json()["questions"]
        assert "correct" not in str(q) and len(q) == 5
        assert c.post("/api/v1/awareness/quiz/submit", json={"answers": [1] * 5}, headers=a).json()["score"] == 5
        assert c.post("/api/v1/awareness/quiz/submit", json={"answers": [1]}, headers=a).status_code == 422
        assert len(c.get("/api/v1/awareness/attempts", headers=a).json()) == 1

def test_training_pipeline_on_SYNTHETIC_test_data(tmp_path, monkeypatch):
    rnd = random.Random(0); rows = []
    for i in range(200):  # synthetic, for pipeline testing only; NOT a real dataset
        rows.append((f"http://secure-bank-verify-{rnd.randint(1,10**6)}.login-update.net/account?id={i}", "phishing"))
        rows.append((f"https://www.site{rnd.randint(1,10**6)}.com/about", "benign"))
    pd.DataFrame(rows, columns=["u", "l"]).to_csv(tmp_path / "d.csv", index=False)
    out = tmp_path / "m.joblib"
    meta = train(str(tmp_path / "d.csv"), "u", "l", str(out))
    assert out.exists() and "f1" in meta["test"] and meta["selected"] in meta["validation"]
    monkeypatch.setenv("MODEL_PATH", str(out))
    p = ml.predict("http://secure-bank-verify-123.login-update.net/account?id=1")
    assert p and 0 <= p["prob"] <= 1
    with TestClient(app) as c:
        h = auth(c, "mluser")
        r = c.post("/api/v1/scans/url", json={"url": "http://secure-bank-verify-1.login-update.net/account"}, headers=h).json()
        assert r["mode"].startswith("trained ML model")
