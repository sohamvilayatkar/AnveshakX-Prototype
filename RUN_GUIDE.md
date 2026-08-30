# 🚀 AnveshakX Quick Run Guide

This quick reference guide walks you through running both the **Backend** and **Frontend** servers concurrently.

---

## ⚡ Quick Start (2 Terminals)

### 🖥️ Terminal 1 — Backend (FastAPI)
```bash
# 1. Navigate to project root
cd "c:\Users\user\Desktop\Programming\Hackathon Project\AnveshakX"

# 2. Install Python dependencies
pip install -r backend/requirements.txt

# 3. Start the FastAPI backend server
python -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000 --reload
```
✅ **Backend is running at:**
- API Root: [http://localhost:8000](http://localhost:8000)
- Interactive API Docs (Swagger): [http://localhost:8000/docs](http://localhost:8000/docs)
- Health Check: [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)

---

### 🌐 Terminal 2 — Frontend (React + Vite)
```bash
# 1. Open a new terminal and navigate to frontend directory
cd "c:\Users\user\Desktop\Programming\Hackathon Project\AnveshakX\frontend"

# 2. Install Node dependencies
npm install

# 3. Start the Vite development server
npm run dev
```
✅ **Frontend SOC Dashboard is running at:**
- Web Dashboard: 👉 **[http://localhost:5173](http://localhost:5173)**

---

## 🧪 Testing with Pre-loaded Demo Scenarios

Once the frontend is open at **[http://localhost:5173](http://localhost:5173)**:
1. Click **"Analyze New Email"** in the top navigation or go to `/upload`.
2. Click any of the **1-Click Demo Buttons**:
   - 🔴 **BEC (CEO Fraud)**: Executive impersonation, Reply-To mismatch, urgent wire transfer request.
   - 🟠 **Credential Phishing**: Account suspension alert with lookalike domain (`.xyz`).
   - 🟣 **Brand Impersonation & Malware**: Microsoft 365 notice with double-extension executable attachment (`invoice_overdue_scan.pdf.exe`).
   - 🟢 **Legitimate Email**: Standard corporate communication with passing SPF, DKIM, and DMARC.
3. Review the **Explainable Threat Score (0–100)**, **Interactive Attack Graph**, **Leaflet Geolocation Map**, and **Download the Forensic PDF Report**.

---

## 🧪 Running Backend Unit Tests

In any terminal:
```bash
pytest backend/tests/ -v
```
All 19 tests will execute and verify the email parser, header analyzer, lookalike detector, rule engine, risk scoring, and PDF report generator.
