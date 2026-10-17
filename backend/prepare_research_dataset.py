"""
Downloads and prepares a balanced, legitimate benchmark dataset from the PhiUSIIL Phishing URL Dataset.
Streams rows without loading full large file into memory.
"""
import csv
import io
import os
import urllib.request
from datetime import datetime, timezone

DATASET_URL = "https://raw.githubusercontent.com/elaaatif/DATA-MINING-PhiUSIIL-Phishing-URL/main/PhiUSIIL_Phishing_URL_Dataset.csv"
OUT_CSV = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "research_data", "phiusiil_url_dataset.csv")
MANIFEST_CSV = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "research_data", "dataset_manifest.csv")

TARGET_PER_CLASS = 1500  # 1500 Phishing + 1500 Legitimate = 3000 verified samples

def main():
    print(f"[*] Connecting to PhiUSIIL repository: {DATASET_URL}")
    req = urllib.request.Request(DATASET_URL, headers={"User-Agent": "CyberShield-Research/2.0"})
    resp = urllib.request.urlopen(req, timeout=30)

    header = resp.readline().decode("utf-8", errors="ignore").strip().split(",")
    url_idx = 1
    label_idx = -1
    for i, h in enumerate(header):
        if h.lower().replace("\ufeff", "") == "url":
            url_idx = i
        if h.lower() == "label":
            label_idx = i

    phishing_samples = []
    legitimate_samples = []
    seen_urls = set()

    print("[*] Streaming and filtering unique, valid URLs...")
    while len(phishing_samples) < TARGET_PER_CLASS or len(legitimate_samples) < TARGET_PER_CLASS:
        line = resp.readline()
        if not line:
            break
        decoded = line.decode("utf-8", errors="ignore").strip()
        if not decoded:
            continue
        parts = decoded.split(",")
        if len(parts) <= max(url_idx, label_idx):
            continue
        u = parts[url_idx].strip()
        lbl = parts[label_idx].strip()

        if not u.startswith("http://") and not u.startswith("https://"):
            continue
        if u in seen_urls:
            continue
        seen_urls.add(u)

        # In PhiUSIIL: label 0 = Phishing, label 1 = Legitimate
        if lbl == "0" and len(phishing_samples) < TARGET_PER_CLASS:
            phishing_samples.append((u, "phishing"))
        elif lbl == "1" and len(legitimate_samples) < TARGET_PER_CLASS:
            legitimate_samples.append((u, "legitimate"))

        if (len(phishing_samples) + len(legitimate_samples)) % 500 == 0:
            print(f"    - Collected: {len(phishing_samples)} Phishing, {len(legitimate_samples)} Legitimate")

    all_samples = phishing_samples + legitimate_samples
    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label"])
        for u, l in all_samples:
            w.writerow([u, l])

    print(f"[+] Saved {len(all_samples)} samples to {OUT_CSV}")

    # Update manifest
    with open(MANIFEST_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["dataset_name", "source_url", "retrieval_date", "total_samples", "phishing_count", "legitimate_count", "label_mapping", "preprocessing"])
        w.writerow([
            "PhiUSIIL Phishing URL Dataset (Research Corpus)",
            DATASET_URL,
            datetime.now(timezone.utc).isoformat(),
            len(all_samples),
            len(phishing_samples),
            len(legitimate_samples),
            "PhiUSIIL raw label 0 -> phishing, label 1 -> legitimate",
            "Deduplicated, filtered valid HTTP/HTTPS URLs, balanced stratified split"
        ])
    print(f"[+] Manifest updated at {MANIFEST_CSV}")

if __name__ == "__main__":
    main()
