# CyberShield — An Intelligent Cyber Threat Detection and Security Assessment Platform

**CyberShield** is an advanced, multi-layered cyber threat detection and security assessment platform combining machine learning URL phishing detection, static heuristic file inspection, and a genuine local Windows system security & malware scanner with Microsoft Defender integration.

---

## 🌟 Key Features

### 1. Genuine Local System Security & Malware Scanner (New)
* **Scan Modes**:
  - **Quick Scan**: Audits high-risk persistence paths including user Startup folders, Windows Autorun Registry keys (`HKCU\Run`, `HKLM\Run`, `RunOnce`), `%TEMP%`, Downloads, and initiates a Microsoft Defender quick scan.
  - **Full System Scan**: Safely scans accessible files across system drives using chunked streaming SHA-256 hashing without loading large files into memory. Automatically handles locked system files and permission boundaries.
  - **Custom Scan**: Allows scanning user-specified folders or files with strict path validation (blocks UNC injection and device namespaces).
* **Hybrid Malware Detection Engine**:
  - Integrates natively with **Microsoft Defender Antivirus** (`MpCmdRun.exe` CLI with `-DisableRemediation`).
  - Verifies hashes against an extensible verified threat signature database (e.g., test signatures, reference ransomware hashes).
  - Inspects Windows startup persistence for encoded PowerShell payloads, hidden windows, and script droppers.
  - Detects deceptive double extensions (e.g. `*.pdf.exe`, `*.docx.vbs`) and disguised PE/MZ binaries.
* **Operational Safety & Safeguards**:
  - Non-destructive by design: files are **never** automatically deleted.
  - Supports explicit user-authorized **Quarantine** to an isolated directory.
  - Live background scanning with **Pause**, **Resume**, and **Cancel** controls.
  - Exportable executive **PDF Security Reports** and **CSV Findings Reports**.

### 2. High-Accuracy URL Phishing Detection ML Pipeline
* **30 Advanced Discriminative Features**:
  - Lexical & syntactic features: URL length, hostname length, path depth, query length, subdomain counts, hyphens, underscores, slashes, digits, ratios.
  - **Information-Theoretic Shannon Entropy**: Computes character entropy for hostnames and full URLs to detect algorithmic domain generation (DGA) and obfuscation.
  - Brand imitation detection in subdomains/paths vs root domain.
  - High-abuse TLD classification and suspicious keyword counters.
* **Leakage-Resistant Multi-Algorithm Comparison**:
  - Strict stratified 60/20/20 train/validation/test split on 3,000 balanced samples from the reputable **PhiUSIIL Phishing URL Dataset**.
  - Compared algorithms: Logistic Regression, Decision Tree, Random Forest, Extra Trees, and HistGradientBoosting.
  - Model selection based on validation F1 and recall, followed by a single evaluation on independent held-out test data.
* **Empirical Research Performance**:
  - **Overall Accuracy**: **99.50%** (vs 52.00% Baseline Heuristic — **+47.50% Gain**)
  - **Phishing Recall**: **99.00%** (vs 4.00% Baseline Heuristic — **+95.00% Gain**)
  - **F1-Score**: **0.9950** (vs 0.0769 Baseline Heuristic)
  - **False Negative Rate**: Reduced from **96.00%** down to **1.00%** (95% reduction in missed threats)
  - **ROC-AUC**: **0.9989**
  - **Inference Latency**: **~0.005 ms** per URL

### 3. Static File Threat Analyzer
* Inspects file headers, magic bytes, macro-enabled documents, archive ratios, and zip bomb indicators without ever executing or extracting untrusted payloads.

### 4. Interactive Threat Intelligence Dashboard
* Real-time metrics overview, visual activity history, security awareness quiz, PDF/CSV report exports, and model benchmark visualizer.

---

## 🛠️ Architecture & Tech Stack

```
┌────────────────────────────────────────────────────────┐
│           React 18 + TypeScript + Vite + Tailwind      │
│  (Dashboard, System Scanner, Model Benchmark, History) │
└───────────────────────────┬────────────────────────────┘
                            │ REST APIs / JWT Bearer
┌───────────────────────────▼────────────────────────────┐
│                  FastAPI 0.141 Backend                 │
│  (Routes, Background Threads, Auth, ReportLab PDFs)    │
└─────────────┬───────────────────────────┬──────────────┘
              │                           │
┌─────────────▼─────────────┐   ┌─────────▼──────────────┐
│  Local System Scanner     │   │  Trained ML Pipeline   │
│  - MpCmdRun.exe (Defender)│   │  - ExtraTrees (30 feats)
│  - Registry Autorun Audit │   │  - StandardScaler      │
│  - Chunked SHA-256 Hashing│   │  - Heuristic Fallback  │
│  - Safe Quarantine Folder │   └────────────────────────┘
└─────────────┬─────────────┘
              │
┌─────────────▼─────────────┐
│  SQLite / SQLAlchemy 2.0  │
│  (Scans, Findings, Users) │
└───────────────────────────┘
```

---

## 🚀 Prerequisites

- **Windows 10 / 11**
- **Python 3.10+** (tested on Python 3.14)
- **Node.js 18+ LTS** and **npm**

---

## 💻 Exact Setup & Execution Commands

### Step 1: Open PowerShell
Open PowerShell in the project directory:
```powershell
cd C:\Users\Asus\.antigravity\CyberShieldA
```

### Step 2: Run Automated Environment Setup
```powershell
# Allows running setup scripts in current PowerShell session
Set-ExecutionPolicy -Scope Process RemoteSigned

# Run setup script (creates virtual environment and sets backend .env with random SECRET_KEY)
.\scripts\setup.ps1
```

### Step 3: Run the FastAPI Backend
In Terminal 1:
```powershell
.\scripts\start_backend.ps1
# API server starts at http://127.0.0.1:8000
# Interactive Swagger Documentation available at http://127.0.0.1:8000/docs
```

### Step 4: Run the React Frontend
In Terminal 2:
```powershell
.\scripts\start_frontend.ps1
# Frontend starts at http://localhost:5173
```

---

## 🧪 Training & Machine Learning Reproduction

To download the verified PhiUSIIL dataset, train candidate models, compare validation performance, and save the champion ExtraTrees model:

```powershell
cd backend

# Step A: Download & prepare balanced 3,000-sample benchmark dataset
python prepare_research_dataset.py

# Step B: Train candidate models with leakage-resistant stratified split
python training/train_model.py ..\research_data\phiusiil_url_dataset.csv --url-col url --label-col label --out models/url_model.joblib

# Step C: Re-generate research paper artifacts and figures
python generate_research_artifacts.py
python generate_research_pdf.py
```

The resulting model artifact `url_model.joblib` and metrics `url_model.metrics.json` are automatically loaded by the backend without requiring manual configuration.

---

## 🛡️ Running Automated Tests

Run the complete test suite (17 automated unit and integration tests):

```powershell
cd backend
python -m pytest -v --junitxml=test_results.xml
python generate_test_report_pdf.py
```

Test coverage includes:
- URL feature extraction robustness and entropy calculation
- Malformed, empty, and Unicode URL edge cases
- Model loading, inference latency, and fallback behavior
- System scanner path validation and boundary defense
- Chunked streaming hashing and signature database lookups
- Microsoft Defender status and engine fallback
- Scan state lifecycle (Start, Pause, Resume, Cancel)
- Non-destructive explicit quarantine confirmation
- PDF and CSV report generation
- Authentication, authorization, and multi-user data isolation

To test frontend compilation:
```powershell
cd ..\frontend
npm.cmd run build
```

---

## 📄 Research Evidence & Academic Paper Artifacts

All experimental data, baseline vs improved metrics, confusion matrices, and the IEEE-format research evaluation report are stored in `research_data/`:

| File | Description |
|---|---|
| `CyberShield_Research_Paper_Experimental_Results.pdf` | Comprehensive IEEE-format experimental results paper |
| `CyberShield_Test_Report.pdf` | Automated test suite execution & verification report (17/17 passed) |
| `model_metrics.json` | Full empirical metrics (Accuracy, F1, ROC-AUC, FPR, FNR, latencies) |
| `confusion_matrix.png` | High-resolution visual confusion matrix |
| `latency_performance.png` | Component processing and inference latency benchmark chart |
| `confusion_matrix.csv` | Baseline vs Improved model confusion matrix data |
| `system_scan_benchmark.csv` | Empirical scan duration and file examination benchmark |
| `dataset_manifest.csv` | Dataset provenance, source URL, split date, and class balance |

---

## 🔒 Security & Privacy Notice
- CyberShield is an academic threat assessment and cyber defense prototype.
- Scans are non-destructive; malicious files are never automatically executed or deleted.
- All dynamic data is served via authenticated local REST endpoints (`localhost`).
