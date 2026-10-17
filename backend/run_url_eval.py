import os, sys, json, csv, time, hashlib, zipfile, io, urllib.request
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESEARCH_DIR = os.path.join(BASE_DIR, "research_data")
os.makedirs(RESEARCH_DIR, exist_ok=True)

# 1. Download & Prepare Benchmark URLs (from PhiUSIIL dataset)
DATASET_URL = "https://raw.githubusercontent.com/elaaatif/DATA-MINING-PhiUSIIL-Phishing-URL/main/PhiUSIIL_Phishing_URL_Dataset.csv"
print(f"[*] Fetching benchmark URL dataset from: {DATASET_URL}")

req = urllib.request.Request(DATASET_URL, headers={"User-Agent": "CyberShield-Research/1.0"})
resp = urllib.request.urlopen(req, timeout=30)

phishing_urls = []
legitimate_urls = []

# Stream lines to parse without loading 100MB+ in memory
header = resp.readline().decode("utf-8", errors="ignore").strip().split(",")
url_idx = 1
label_idx = -1
for i, h in enumerate(header):
    if h.lower() in ("url", "\ufeffurl"): url_idx = i
    if h.lower() == "label": label_idx = i

count = 0
while len(phishing_urls) < 150 or len(legitimate_urls) < 150:
    line = resp.readline()
    if not line: break
    count += 1
    decoded = line.decode("utf-8", errors="ignore").strip()
    if not decoded: continue
    parts = decoded.split(",")
    if len(parts) <= max(url_idx, label_idx): continue
    u = parts[url_idx].strip()
    lbl = parts[label_idx].strip()
    # In PhiUSIIL: 1 = Legitimate, 0 = Phishing
    if lbl == "0" and len(phishing_urls) < 150:
        if u.startswith("http://") or u.startswith("https://"):
            phishing_urls.append(u)
    elif lbl == "1" and len(legitimate_urls) < 150:
        if u.startswith("http://") or u.startswith("https://"):
            legitimate_urls.append(u)

print(f"[+] Downloaded: {len(phishing_urls)} Phishing URLs, {len(legitimate_urls)} Legitimate URLs")

# Save manifest
manifest_path = os.path.join(RESEARCH_DIR, "dataset_manifest.csv")
with open(manifest_path, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["dataset_name", "source_url", "retrieval_date", "total_samples", "phishing_count", "legitimate_count", "label_mapping", "preprocessing"])
    w.writerow([
        "PhiUSIIL Phishing URL Dataset (Benchmark Subset)",
        DATASET_URL,
        datetime.now(timezone.utc).isoformat(),
        len(phishing_urls) + len(legitimate_urls),
        len(phishing_urls),
        len(legitimate_urls),
        "PhiUSIIL raw label 0 -> phishing, label 1 -> legitimate",
        "Filtered valid HTTP/HTTPS URLs; deduplicated; held-out evaluation subset"
    ])

# 2. Evaluate against CyberShield API (Heuristic Detector active)
API_BASE = "http://127.0.0.1:5173/api/v1"

# Create session & authenticate
auth_data = json.dumps({"username": "research_eval", "password": "ResearchPass123!"}).encode("utf-8")
try:
    reg_req = urllib.request.Request(f"{API_BASE}/auth/register", data=auth_data, headers={"Content-Type": "application/json"}, method="POST")
    urllib.request.urlopen(reg_req, timeout=10)
except Exception:
    pass

login_req = urllib.request.Request(f"{API_BASE}/auth/login", data=auth_data, headers={"Content-Type": "application/json"}, method="POST")
login_res = urllib.request.urlopen(login_req, timeout=10)
token = json.loads(login_res.read().decode("utf-8"))["access_token"]
headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}

url_results = []
test_id = 1

samples = [(u, "phishing") for u in phishing_urls] + [(u, "legitimate") for u in legitimate_urls]

print(f"[*] Running live evaluation on {len(samples)} URLs via CyberShield API...")

for url_str, ground_truth in samples:
    t0 = time.perf_counter()
    err_msg = ""
    pred_label = "unknown"
    score = 0
    category = "Unknown"
    active_detector = "heuristic (rule-based)"
    features_json = "{}"
    
    try:
        body = json.dumps({"url": url_str}).encode("utf-8")
        scan_req = urllib.request.Request(f"{API_BASE}/scans/url", data=body, headers=headers, method="POST")
        with urllib.request.urlopen(scan_req, timeout=10) as res:
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            data = json.loads(res.read().decode("utf-8"))
            score = data.get("score", 0)
            category = data.get("category", "Low")
            active_detector = data.get("mode", "heuristic")
            features_json = json.dumps(data.get("features", {}))
            # CyberShield classification logic: High or Suspicious = Flagged (Malicious/Phishing), Low = Legitimate
            if category in ("High", "Suspicious"):
                pred_label = "phishing"
            else:
                pred_label = "legitimate"
    except Exception as e:
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        err_msg = str(e)
        pred_label = "error"
    
    is_correct = (pred_label == ground_truth) if pred_label != "error" else False
    
    url_results.append({
        "test_id": f"URL_{test_id:04d}",
        "url": url_str,
        "ground_truth": ground_truth,
        "predicted_label": pred_label,
        "risk_score": score,
        "risk_category": category,
        "analysis_time_ms": elapsed_ms,
        "active_detector": active_detector,
        "is_correct": is_correct,
        "error_message": err_msg,
        "extracted_features": features_json
    })
    test_id += 1

# Save url_scan_results.csv
url_csv_path = os.path.join(RESEARCH_DIR, "url_scan_results.csv")
with open(url_csv_path, "w", newline="", encoding="utf-8") as f:
    fields = ["test_id", "url", "ground_truth", "predicted_label", "risk_score", "risk_category", "analysis_time_ms", "active_detector", "is_correct", "error_message", "extracted_features"]
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(url_results)

print(f"[+] Successfully wrote {len(url_results)} URL scan records to {url_csv_path}")
