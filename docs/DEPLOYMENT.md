# 🚀 AnveshakX Deployment Guide: Render (Backend) + Netlify (Frontend)

This guide walks you step-by-step through deploying **AnveshakX** to production using **Render** for the Python/FastAPI backend and **Netlify** for the React/Vite frontend.

---

## 📋 Overview of the Deployment Architecture

```
                               ┌──────────────────────────────────────────────┐
                               │             USER'S BROWSER                   │
                               └──────────────────────┬───────────────────────┘
                                                      │
                                                      │ HTTPS Requests
                                                      ▼
                      ┌────────────────────────────────────────────────────────┐
                      │                 NETLIFY (FRONTEND)                     │
                      │         https://anveshakx-soc.netlify.app              │
                      │  • React 18 + Vite Production Static Bundle            │
                      │  • Netlify SPA Redirects (/* -> /index.html)           │
                      │  • Communicates with Render backend via VITE_API_URL   │
                      └───────────────────────┬────────────────────────────────┘
                                              │
                                              │ API calls (/api/v1/...)
                                              ▼
                      ┌────────────────────────────────────────────────────────┐
                      │                  RENDER (BACKEND)                      │
                      │       https://anveshakx-backend.onrender.com           │
                      │  • FastAPI + Uvicorn Python Web Service                │
                      │  • Phase 1 Forensic Parsing & Threat Intelligence      │
                      │  • Phase 2 AI/ML Models (TF-IDF, Logistic Regression)  │
                      │  • PDF Forensic Report Generation                      │
                      └────────────────────────────────────────────────────────┘
```

---

## 🛠️ Step 0: Push Your Code to GitHub

Make sure your project is committed and pushed to a GitHub repository:

```bash
git add .
git commit -m "feat: complete AnveshakX Phase 1 & 2 with deployment config"
git push origin main
```

---

## 🐍 PART 1: Deploy Backend on Render

> **Tip**: Deploy the backend first so you get your Render live URL (e.g., `https://anveshakx-backend.onrender.com`), which you'll need when deploying the frontend on Netlify.

### Method A: Manual Web Service Setup (Recommended)

1. Go to **[render.com](https://render.com)** and log in (sign up with GitHub if you haven't).
2. On your Render Dashboard, click **New +** and select **Web Service**.
3. Select your **AnveshakX** GitHub repository and click **Connect**.
4. Configure the Web Service settings:

| Setting Field | Value |
|---|---|
| **Name** | `anveshakx-backend` *(or your preferred name)* |
| **Region** | Choose nearest (e.g. *Oregon (US West)* or *Frankfurt (EU)*) |
| **Branch** | `main` |
| **Root Directory** | Leave blank *(root of repo)* |
| **Runtime** | `Python 3` |
| **Build Command** | `pip install -r requirements.txt && python -m ml.training.train_classifier && python -m ml.training.train_anomaly` |
| **Start Command** | `uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port $PORT` |
| **Instance Type** | `Free` |

5. Scroll down to **Environment Variables** and add:

| Key | Value | Description |
|---|---|---|
| `APP_ENV` | `production` | Production environment mode |
| `ML_ENABLED` | `true` | Enables Phase 2 AI/ML models |
| `CORS_ORIGINS` | `*` | Or specify your Netlify URL |
| `PYTHON_VERSION` | `3.11.8` | Recommended stable Python runtime |

6. Click **Create Web Service**.
7. Wait ~2–3 minutes for Render to build dependencies, train the ML models, and start the Uvicorn server.
8. Once the status shows **Live**, copy your Render URL at the top:  
   👉 `https://anveshakx-backend.onrender.com` *(example)*

#### Verify Backend:
Open `https://your-backend-name.onrender.com/api/v1/health` in your browser. You should see:
```json
{
  "status": "healthy",
  "app_name": "AnveshakX",
  "version": "1.0.0",
  "database": "healthy",
  "capabilities": {
    "ml_engine": true,
    "ip_intelligence": true,
    "domain_intelligence": false
  }
}
```

---

## ⚡ PART 2: Deploy Frontend on Netlify

### Method A: Connect with Git (Automatic CI/CD — Recommended)

1. Go to **[netlify.com](https://netlify.com)** and log in with your GitHub account.
2. Click **Add new site** > **Import an existing project**.
3. Choose **GitHub** and select your **AnveshakX** repository.
4. Configure the Netlify site build settings:

| Setting Field | Value |
|---|---|
| **Base directory** | `frontend` |
| **Build command** | `npm run build` |
| **Publish directory** | `dist` *(or `frontend/dist` if base is blank)* |

5. Click **Add environment variables** (or go to *Site configuration* > *Environment variables*) and add:

| Variable Key | Value |
|---|---|
| `VITE_API_URL` | `https://anveshakx-backend.onrender.com` *(Paste your Render backend URL without trailing slash)* |

6. Click **Deploy Site**.
7. Netlify will run Vite build and deploy your site in ~30–45 seconds.
8. Netlify will give you a live URL like:  
   👉 `https://anveshakx-forensics.netlify.app`

*(You can customize this domain anytime under Site settings > Change site name).*

---

### Method B: Manual Drag-and-Drop Deploy (Alternative / Quick Test)

If you prefer building locally and uploading:

1. In your local terminal, build the frontend with your Render backend URL:
   ```bash
   cd frontend
   # Windows (PowerShell)
   $env:VITE_API_URL="https://your-backend-name.onrender.com"
   npm run build
   ```
2. Log into **[app.netlify.com/drop](https://app.netlify.com/drop)**.
3. Drag and drop the `frontend/dist` folder into the Netlify Drop box.
4. Your site will be live immediately!

---

## 🧪 Step 3: End-to-End Verification

1. Open your live Netlify frontend URL (e.g., `https://anveshakx-soc.netlify.app`).
2. Navigate to `/upload` (or click **"Analyze New Email"**).
3. Test a 1-Click Demo sample:
   - Click **"Business Email Compromise (CEO Fraud)"**.
   - Verify that the threat score displays **87 / 100 CRITICAL**, Phase 1 headers are populated, Phase 2 AI signals are classified, and the **Forensic PDF Report** downloads successfully.
4. Test direct page refreshing on `/upload`, `/analysis`, and `/cases` to verify SPA routing (`_redirects` rule).

---

## ⚙️ Important Troubleshooting & Tips

### 1. Render Free Tier Sleep Mode (Cold Starts)
- On Render's free tier, services spin down after 15 minutes of inactivity.
- When you first visit after being idle, the backend takes ~30–45 seconds to spin up.
- The frontend Axios client is configured with a 45-second timeout to handle cold starts gracefully.

### 2. Updating CORS after Netlify is Live
If you want to restrict CORS strictly to your Netlify domain instead of `*`:
1. In Render Dashboard > your Web Service > **Environment**.
2. Update `CORS_ORIGINS` to `https://your-site-name.netlify.app`.
3. Render will redeploy automatically with the new origin.

### 3. SPA 404 on Refresh
- Netlify uses the included `frontend/public/_redirects` file (`/* /index.html 200`) and `netlify.toml` to ensure React Router routes work seamlessly when refreshed or bookmarked.
