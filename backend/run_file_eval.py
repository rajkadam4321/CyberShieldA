import os, sys, json, csv, time, hashlib, zipfile, io, urllib.request

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESEARCH_DIR = os.path.join(BASE_DIR, "research_data")
API_BASE = "http://127.0.0.1:5173/api/v1"

# Login
auth_data = json.dumps({"username": "research_eval", "password": "ResearchPass123!"}).encode("utf-8")
login_req = urllib.request.Request(f"{API_BASE}/auth/login", data=auth_data, headers={"Content-Type": "application/json"}, method="POST")
login_res = urllib.request.urlopen(login_req, timeout=10)
token = json.loads(login_res.read().decode("utf-8"))["access_token"]
headers = {"Authorization": f"Bearer {token}"}

# Create test files in memory
test_samples = []

# 1. Benign PDF
benign_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000060 00000 n \n0000000117 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n168\n%%EOF\n"
test_samples.append(("sample_clean_document.pdf", benign_pdf, "benign", "Valid PDF header and document structure"))

# 2. Benign Text
benign_txt = b"CyberShield Security Research Evaluation Test File.\nLegitimate benign content."
test_samples.append(("readme_notes.txt", benign_txt, "benign", "Plain text documentation"))

# 3. Benign PNG image
png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
test_samples.append(("avatar_clean.png", png_bytes, "benign", "Valid PNG image binary"))

# 4. Benign ZIP archive
zip_buf = io.BytesIO()
with zipfile.ZipFile(zip_buf, "w") as zf:
    zf.writestr("notes.txt", "Clean plain text inside zip archive.")
test_samples.append(("clean_archive.zip", zip_buf.getvalue(), "benign", "Single benign text file in ZIP"))

# 5. Dangerous script file (.ps1)
test_samples.append(("deploy_automation.ps1", b"Write-Host 'System Administration Script'", "suspicious", "Executable script extension (.ps1)"))

# 6. Dangerous batch file (.bat)
test_samples.append(("installer.bat", b"@echo off\necho Installing...", "suspicious", "Executable script extension (.bat)"))

# 7. Dangerous binary executable (.exe)
test_samples.append(("binary_tool.exe", b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00", "suspicious", "Windows PE executable header and extension"))

# 8. Double extension attack (invoice.pdf.exe)
test_samples.append(("urgent_invoice_october.pdf.exe", b"MZ\x90\x00dummy-executable-payload", "malicious", "Double extension masquerading doc as executable"))

# 9. Extension/signature mismatch (EXE masquerading as PDF)
test_samples.append(("annual_report_2026.pdf", b"MZ\x90\x00\x03\x00\x00\x00Windows Executable Header Hidden", "malicious", "PE header hidden under .pdf extension"))

# 10. Macro-enabled Office document (.docm)
test_samples.append(("financial_statement.docm", b"PK\x03\x04\x14\x00\x06\x00Office Macro Document", "suspicious", "Macro-enabled office document format"))

# 11. Archive with hidden executable
zip_bad = io.BytesIO()
with zipfile.ZipFile(zip_bad, "w") as zf:
    zf.writestr("document.pdf", "harmless text")
    zf.writestr("payload.exe", b"MZ\x90\x00executable")
test_samples.append(("confidential_docs.zip", zip_bad.getvalue(), "malicious", "Archive containing executable file payload.exe"))

# 12. Path traversal attack inside archive
zip_traversal = io.BytesIO()
with zipfile.ZipFile(zip_traversal, "w") as zf:
    zf.writestr("../../etc/passwd", "root:x:0:0::/root:/bin/bash")
test_samples.append(("system_patch.zip", zip_traversal.getvalue(), "malicious", "Archive entry attempting directory traversal path"))

# 13. Corrupted ZIP archive
test_samples.append(("damaged_archive.zip", b"PK\x03\x04incomplete-corrupt-data", "suspicious", "Corrupt ZIP file header without valid directory"))

# 14. Linux ELF executable disguised as TXT
test_samples.append(("readme.txt", b"\x7fELF\x02\x01\x01\x00Linux Binary Header", "malicious", "ELF binary header hidden under .txt extension"))

# 15. Unsupported / oversized simulation (tested via normal endpoint)
test_samples.append(("script_payload.vbs", b"WScript.Echo 'VisualBasic script payload'", "suspicious", "VisualBasic script extension (.vbs)"))

print(f"[*] Testing {len(test_samples)} file samples against CyberShield file analysis API...")

file_results = []
test_id = 1

def send_file_multipart(filename, data, headers):
    boundary = "----WebKitFormBoundaryCyberShieldResearch"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode("utf-8") + data + f"\r\n--{boundary}--\r\n".encode("utf-8")
    
    req_headers = dict(headers)
    req_headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    req = urllib.request.Request(f"{API_BASE}/scans/file", data=body, headers=req_headers, method="POST")
    return req

for filename, data, ground_truth, note in test_samples:
    t0 = time.perf_counter()
    err_msg = ""
    pred_label = "unknown"
    score = 0
    category = "Unknown"
    detected_indicators = []
    
    try:
        req = send_file_multipart(filename, data, headers)
        with urllib.request.urlopen(req, timeout=10) as res:
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            res_data = json.loads(res.read().decode("utf-8"))
            score = res_data.get("score", 0)
            category = res_data.get("category", "Low")
            findings = res_data.get("findings", [])
            detected_indicators = [f"{f['indicator']} (+{f['points']} pts)" for f in findings]
            
            if category == "High":
                pred_label = "malicious"
            elif category == "Suspicious":
                pred_label = "suspicious"
            else:
                pred_label = "benign"
    except Exception as e:
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        err_msg = str(e)
        pred_label = "error"
        
    is_correct = (pred_label == ground_truth) if pred_label != "error" else False
    
    file_results.append({
        "test_id": f"FILE_{test_id:03d}",
        "filename": filename,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest()[:16] + "...",
        "ground_truth": ground_truth,
        "predicted_label": pred_label,
        "risk_score": score,
        "risk_category": category,
        "analysis_time_ms": elapsed_ms,
        "detected_indicators": "; ".join(detected_indicators) if detected_indicators else "None",
        "is_correct": is_correct,
        "note": note,
        "error_message": err_msg
    })
    test_id += 1

file_csv_path = os.path.join(RESEARCH_DIR, "file_scan_results.csv")
with open(file_csv_path, "w", newline="", encoding="utf-8") as f:
    fields = ["test_id", "filename", "size_bytes", "sha256", "ground_truth", "predicted_label", "risk_score", "risk_category", "analysis_time_ms", "detected_indicators", "is_correct", "note", "error_message"]
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(file_results)

print(f"[+] Successfully wrote {len(file_results)} file scan records to {file_csv_path}")
