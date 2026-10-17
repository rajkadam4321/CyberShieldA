# CyberShield Research Data Manifest & Experimental Benchmark Documentation

## 1. Overview & System State
- **Project Title:** CyberShield: An Intelligent Cyber Threat Detection and Security Assessment Platform
- **Evaluation Date:** October 14, 2026
- **Operating Environment:** Windows 11 x64, Python 3.14.5, Node.js + Vite v6.4.4, FastAPI 0.141.1, SQLite 3
- **Active URL Detection Engine:** Heuristic rule-based lexical scoring engine (`app/url_analysis.py`).
  - *Note on ML Pipeline:* The codebase includes an automated scikit-learn training pipeline (`training/train_model.py`) and inference loader (`app/ml.py`). However, no pre-trained weights (`models/url_model.joblib`) were committed or active out-of-the-box in the repository. As per IEEE research integrity standards, URL classification experiments were executed on the active real-world heuristic engine.
- **Active File Analysis Engine:** Static structural and signature heuristic analyzer (`app/file_analysis.py`). Never executes or extracts arbitrary code.

---

## 2. Benchmark Datasets & Provenance

### URL Benchmark
- **Source:** PhiUSIIL Phishing URL Dataset (Mendeley Data DOI: 10.17632/shwpxscxy2.2 / UCI Machine Learning Repository #967)
- **Sample Size:** 300 balanced URLs (150 Phishing, 150 Legitimate)
- **Label Mapping:** PhiUSIIL raw label `0` -> Phishing; raw label `1` -> Legitimate
- **Detection Decision Rule:**
  - CyberShield Risk Category `High` (Score ≥ 60) or `Suspicious` (Score 30–59) = Predicted Malicious/Phishing
  - CyberShield Risk Category `Low` (Score < 30) = Predicted Legitimate/Benign

### File Analysis Benchmark
- **Sample Size:** 15 safe structural test files covering benign formats (PDF, PNG, TXT, ZIP) and threat vectors (double extensions, PE header mismatch, script extensions `.ps1`, `.bat`, `.vbs`, macro office formats `.docm`, zip path traversal).

---

## 3. Experimental Metrics Summary

### A. URL Detection Performance (Heuristic Baseline Engine)
- **Total Tested:** 300 URLs
- **True Positives (TP):** 6
- **True Negatives (TN):** 150
- **False Positives (FP):** 0
- **False Negatives (FN):** 144
- **Accuracy:** 52.0%
- **Precision:** 100.0% (Zero false alarms on benign URLs)
- **Recall:** 4.0% (High false negative rate against modern domain-based phishing)
- **F1-Score:** 0.0769
- **Key Insight for Research Paper:** The lexical heuristic rules exhibit exceptional specificity / precision (1.000) by avoiding false accusations of legitimate domains, but suffer from low sensitivity (0.040) against obfuscated or clean-looking phishing domains that lack raw IP hosts or specific suspicious keywords. This mathematically justifies the need for trained ML / transformer classifiers.

### B. File Analysis Evaluation
- **Total Tested:** 15 structural test files
- **Benign Clean Files:** 4 / 4 correctly identified as Low Risk (100% specificity)
- **Double Extension Attack:** Flagged as High Risk (Score: 65/100, Detected indicators: double extension + dangerous extension)
- **Signature / Mismatch Attacks:** Correctly detected PE inside PDF and ELF inside TXT.

### C. System Latency & Performance (at 50 Repetitions)
- **Health Check (Public):** Mean Latency = 9.60 ms | Median = 4.22 ms | P95 = 28.51 ms | Throughput = 104.09 RPS
- **Dashboard Metrics (Authenticated):** Mean Latency = 15.69 ms | Median = 8.01 ms | P95 = 31.99 ms | Throughput = 63.71 RPS
- **Scan History Query (Authenticated):** Mean Latency = 14.98 ms | Median = 8.66 ms | P95 = 34.58 ms | Throughput = 66.72 RPS
- **URL Heuristic Analysis (Authenticated):** Mean Latency = 20.54 ms | Median = 13.52 ms | P95 = 65.57 ms | Throughput = 48.67 RPS
- **API Success Rate:** 100.0% (0 errors across all load profiles)

### D. Security & Control Tests
- **Total Test Cases:** 15
- **Passed:** 15 / 15 (100%)
- **Verified Protections:** Length validation, character sanitization, bcrypt-style PBKDF2 password hashing, JWT expiration, IDOR access protection, and isolated multi-tenant history exports.

---

## 4. Directory Artifacts

| Filename | Description |
|---|---|
| `dataset_manifest.csv` | Dataset source, retrieval URL, sampling methodology, and label mapping |
| `url_scan_results.csv` | Raw 300-sample live URL scan experimental output with timing, scores, and features |
| `file_scan_results.csv` | Static analysis results across 15 structured test files |
| `performance_results.csv` | Throughput, average, median, p95, and p99 latency across varying workloads |
| `security_test_results.csv` | Formal test results for authentication, validation, and authorization |
| `model_metrics.json` | Calculated precision, recall, F1, accuracy, and confusion matrix |
| `confusion_matrix.csv` | 2x2 contingency matrix of ground truth vs predicted labels |
| `experiment_config.json` | Complete environment specifications, software versions, and runtime config |
| `confusion_matrix.png` | Publication-ready visual contingency chart |
| `latency_performance.png` | Publication-ready API response time benchmark chart |
