# CyberShield – Intelligent Cyber Threat Detection & Security Assessment (academic prototype)
Not a replacement for enterprise security products. Scores are **indicators, not proof**; a low score is **not** a guarantee of safety.

## What it does
React + Vite + TypeScript + Tailwind UI; FastAPI + SQLAlchemy + SQLite backend; JWT auth (PBKDF2 password hashing); URL scanner (never visits the URL);
static file analyzer (never executes/extracts files); history with filter/pagination; dashboard from real DB data; PDF reports; CSV export; awareness quiz with saved attempts.

**Detection modes:** `heuristic (rule-based…)` until you train a model; after training it shows `trained ML model (<name>)`. No dataset or trained model is shipped.

## Prerequisites (Windows)
Python 3.10+ (tick "Add to PATH"), Node.js 18+ LTS. Open **PowerShell** in the `cybershield-app` folder.

## Setup and run
```powershell
cd cybershield-app
.\scripts\setup.ps1            # creates venv, installs packages, creates backend\.env with a random SECRET_KEY
.\scripts\start_backend.ps1    # terminal 1  -> http://127.0.0.1:8000/docs
.\scripts\start_frontend.ps1   # terminal 2  -> http://localhost:5173
```
If scripts are blocked: `Set-ExecutionPolicy -Scope Process RemoteSigned` (affects only that window), then retry. Stop with Ctrl+C. The SQLite DB (`backend\cybershield.db`) is created automatically.

## Train the real model (your own legally obtained, licensed CSV)
```powershell
cd backend
.\.venv\Scripts\python.exe training\train_model.py C:\path\data.csv --url-col url --label-col label
```
Labels accepted: phishing/malicious/bad/malware/1/true vs benign/legitimate/good/safe/0/false. Pipeline: validation, deduplication, same feature extractor as the app, stratified 60/20/20 split,
Logistic Regression vs Random Forest chosen on validation F1, one final test evaluation (accuracy, precision, recall, F1, ROC-AUC, confusion matrix), saves `models\url_model.joblib` + `.metrics.json`.
Restart the backend afterwards. **Warning:** a random split does not prove generalisation to future attacks; add time-based or cross-dataset evaluation for your research.

## Tests
```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest -q
cd ..\frontend
npm run build
```
(The tests train on a tiny SYNTHETIC CSV generated inside the test only to verify the pipeline; it is not real data.)

## Common Windows problems
- `python` not found → reinstall Python with "Add to PATH". 
- Scripts blocked → see execution-policy note above.
- Port 8000/5173 busy → close the other program or change the port.
- Login fails after restart with no `.env` → set `SECRET_KEY` (setup.ps1 does this).
- Upload rejected → file exceeds `MAX_UPLOAD_MB` in `backend\.env`.

## Limits
Static checks cannot detect all malware; file types are limited to the signatures listed in `file_analysis.py`. Not included yet: academic project document, demo checklist, DB seed command.
