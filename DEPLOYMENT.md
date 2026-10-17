# 🚀 CyberShield Cloud Deployment Guide (24/7 Access)

This guide provides step-by-step instructions to deploy **CyberShield** to production using:
- **Frontend:** [Vercel](https://vercel.com) (React 18 + Vite + TypeScript)
- **Backend:** [Render](https://render.com) (FastAPI Web Service)
- **Database:** [Supabase](https://supabase.com) or [Render PostgreSQL](https://render.com) (Managed PostgreSQL)

---

## 📑 Architecture Overview

```
                      HTTPS Request
 [End User Browser] ───────────────► [Vercel Edge Network]
         │                           (React SPA: cybershield.vercel.app)
         │                                   │
         │  REST API Calls with JWT          │
         └─────────────────────────► [Render Web Service]
                                     (FastAPI: cybershield-api.onrender.com)
                                             │
                                             ▼
                                     [Supabase / Render DB]
                                     (Managed PostgreSQL: 5432/6543)
```

---

## 📋 Pre-Deployment Checklist

1. [x] **Frontend:** `frontend/src/api.ts` configured to use `VITE_API_BASE_URL`.
2. [x] **SPA Routing:** `frontend/vercel.json` configured with client-side rewrites.
3. [x] **Backend CORS:** `backend/app/main.py` configured to allow Vercel domains via `CORS_ORIGIN_REGEX`.
4. [x] **PostgreSQL Support:** `psycopg2-binary` added and `DATABASE_URL` normalized in `backend/app/config.py`.
5. [x] **Trained Model:** `backend/models/url_model.joblib` and metrics verified on disk.
6. [x] **Automated Tests:** 17/17 tests passing locally.

---

## 🗄️ Step 1: Set Up Managed PostgreSQL Database

You can use either **Supabase** (recommended, generous free tier) or **Render PostgreSQL**.

### Option A: Supabase (Recommended)
1. Go to [https://supabase.com](https://supabase.com) and sign in with GitHub.
2. Click **New Project**:
   - **Name:** `cybershield-db`
   - **Database Password:** Enter a strong password and save it securely.
   - **Region:** Choose the region closest to you (e.g., `US East` or `Central EU`).
3. Once the database is provisioned (approx. 1-2 minutes):
   - Navigate to **Project Settings** (gear icon) ➔ **Database**.
   - Under **Connection string**, select **URI**.
   - Copy the connection string. It will look like:
     ```
     postgresql://postgres.[YOUR-PROJECT-REF]:[YOUR-PASSWORD]@aws-0-us-east-1.pooler.supabase.com:6543/postgres
     ```
   - Replace `[YOUR-PASSWORD]` with your actual database password.

> **Note:** CyberShield automatically creates all required tables (`users`, `scans`, `system_scans`, `system_scan_findings`, `quiz_attempts`) on initial API startup via SQLAlchemy `init_db()`. No manual SQL migrations are required!

---

## ⚙️ Step 2: Push Code to GitHub

Commit your prepared cloud deployment configuration to your GitHub repository:

```powershell
# In PowerShell at C:\Users\Asus\.antigravity\CyberShieldA
git add .
git commit -m "Configure production deployment for Vercel, Render, and PostgreSQL"
git push origin main
```

---

## 🌐 Step 3: Deploy Backend on Render

1. Go to [https://dashboard.render.com](https://dashboard.render.com) and sign in.
2. Click **New +** ➔ **Web Service**.
3. Select **Build and deploy from a Git repository** and connect `rajkadam4321/CyberShieldA`.
4. Configure the Web Service settings:
   - **Name:** `cybershield-api`
   - **Region:** Choose the same or closest region to your database (e.g., `Ohio (US East)`).
   - **Branch:** `main`
   - **Root Directory:** `backend`
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - **Plan:** `Free` (or `Starter` for 24/7 zero-sleep availability)
5. Scroll down to **Environment Variables** and add:

| Key | Value | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql://postgres.[REF]:[PASS]@[HOST]:[PORT]/postgres` | Your Supabase or PostgreSQL URI |
| `SECRET_KEY` | *(Click "Generate" or paste a random 48-char secret)* | JWT authentication secret |
| `ACCESS_TOKEN_MINUTES` | `1440` | Token lifetime (24 hours) |
| `MAX_UPLOAD_MB` | `5` | File upload limit |
| `CORS_ORIGIN_REGEX` | `^https:\/\/.*\.vercel\.app$` | Allows all Vercel deployments |
| `CORS_ORIGINS` | `https://*.vercel.app,http://localhost:5173` | Explicit allowed origins |

6. Click **Create Web Service**.
7. Wait for the build and deployment to finish (approx. 2-3 minutes).
8. Once live, test the health check in your browser:
   ```
   https://cybershield-api.onrender.com/api/v1/health
   ```
   It should return: `{"status": "ok", "version": "0.2.0"}`.
   Save your backend URL: `https://<YOUR-RENDER-APP>.onrender.com`.

---

## 💻 Step 4: Deploy Frontend on Vercel

1. Go to [https://vercel.com](https://vercel.com) and sign in with GitHub.
2. Click **Add New…** ➔ **Project**.
3. Import the `CyberShieldA` repository.
4. In the **Configure Project** screen:
   - **Framework Preset:** `Vite`
   - **Root Directory:** Click **Edit** and select `frontend` (Important!).
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`
   - **Install Command:** `npm install`
5. Expand **Environment Variables** and add:

| Key | Value |
|---|---|
| `VITE_API_BASE_URL` | `https://<YOUR-RENDER-APP>.onrender.com` |

*(Make sure there is no trailing slash on the URL!)*

6. Click **Deploy**.
7. Vercel will build the React application in ~45 seconds.
8. Once complete, click the deployment link (e.g., `https://cybershield-app.vercel.app`).

---

## 🔄 Step 5: Update Backend CORS with Final Vercel URL

Once Vercel gives you your production URL (e.g. `https://cybershield-app.vercel.app`):
1. Go back to your [Render Dashboard](https://dashboard.render.com).
2. Open your `cybershield-api` service ➔ **Environment**.
3. Update `CORS_ORIGINS`:
   ```
   https://cybershield-app.vercel.app,http://localhost:5173
   ```
4. Click **Save Changes**. Render will automatically redeploy with the updated CORS rule in seconds.

---

## ✅ Post-Deployment Verification Checklist

Verify that all subsystems operate correctly online:

- [ ] **Health Check:** Open `https://<your-render-app>.onrender.com/api/v1/health` ➔ Returns `status: ok`.
- [ ] **Interactive API Docs:** Open `https://<your-render-app>.onrender.com/docs` ➔ Swagger UI loads cleanly.
- [ ] **Frontend Web App:** Open `https://<your-vercel-app>.vercel.app` ➔ Landing hero page renders.
- [ ] **User Registration:** Register a new user account ➔ User is saved to PostgreSQL and JWT is issued.
- [ ] **URL Scanner:** Test a phishing URL ➔ Analyzes URL with the trained ExtraTrees ML model and returns classification.
- [ ] **Static File Analyzer:** Upload a sample file ➔ Static heuristic analysis completes.
- [ ] **Scan History:** Check the History page ➔ Previous scans persist across browser refreshes and service restarts.
- [ ] **PDF Report Export:** Click "Download PDF" on any scan ➔ Formatted ReportLab PDF downloads successfully.
- [ ] **Model Benchmark:** Visit the Model Benchmark page ➔ Confusion matrix and validation metrics render from the backend.

---

## ⚡ Continuous Availability & Free Tier Notes

- **Vercel Frontend:** Runs on Vercel's global CDN and is available 24/7 with zero downtime.
- **Render Backend (Free Tier):**
  - If using Render's Free tier, the service automatically spins down after 15 minutes of inactivity.
  - The first request after sleep will take ~30-50 seconds to wake up (cold start). Subsequent requests are instantaneous (~5-15 ms).
  - To prevent sleep entirely, you can either upgrade to Render Starter ($7/month) or set up a free 5-minute health check ping using [UptimeRobot](https://uptimerobot.com) pointing to `https://<your-render-app>.onrender.com/api/v1/health`.
- **Database (Supabase Free Tier):**
  - Managed PostgreSQL provides 500 MB storage and stays active.
  - If inactive for over a week, Supabase sends an email notification before pausing.
