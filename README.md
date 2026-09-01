# AnveshakX (अन्वेषक-X)

> **AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform**  
> *Smart India Hackathon (SIH) Prototype — Phase 1 (Forensics) + Phase 2 (AI/ML & Behavioral Intelligence)*

---

## 📌 1. Problem Statement

Email remains the primary initial attack vector in over 90% of cyber breaches, including **Business Email Compromise (BEC)**, **Executive Impersonation**, and **Targeted Credential Harvesting**. 

Traditional spam filters operate as black-box classifiers that label messages as "spam" or "ham" without providing explainable evidence. When a high-impact incident occurs, SOC analysts and digital forensics investigators must manually:
- Parse raw headers and extract multi-hop Received lines.
- Map mail transfer agent (MTA) relays across international networks.
- Determine whether SPF/DKIM/DMARC authentication anomalies represent spoofing.
- Correlate lookalike domains and typosquatted brands.
- Analyze linguistic manipulation tactics (urgency, financial pressure, CEO pretexts).
- Preserve chain of custody with cryptographic integrity checksums.

---

## 💡 2. Solution: AnveshakX

**AnveshakX** is a unified cyber forensic and AI threat intelligence platform that converts an untrusted, raw `.eml` email into structured, explainable digital evidence:

$$\text{Final Risk Score} = (0.50 \times \text{Forensic Score}) + (0.30 \times \text{ML Score}) + (0.20 \times \text{Threat Intel Score})$$

---

## ⚡ 3. Unified Phase 1 + Phase 2 Features

- 🧠 **AI/ML Multi-Class Threat Classifier**: TF-IDF + Logistic Regression calibrated model classifying `bec`, `phishing`, `credential_theft`, `financial_fraud`, and `legitimate` with model version tracking (`anveshakx-email-classifier-v2.0`).
- 🎭 **Social Engineering Behavioral Profiler**: Evaluates 7 psychological manipulation dimensions: *Urgency, Financial Pressure, Authority Impersonation, Fear/Coercion, Secrecy, Credential Request, and Call to Action*.
- ⚖️ **Multi-Layer Risk Fusion Engine**: Weighted synthesis of Forensic Evidence (50%), AI Language Predictions (30%), and Threat Intelligence (20%).
- 🔎 **"Why Was This Flagged?" Triage Matrix**: Tri-pane explainability separating Technical Signals, AI Linguistic Signals, and Threat Intelligence.
- 🎯 **Campaign & Similar-Case Intelligence**: Identifies cluster signatures and shared forensic traits against past cases.
- 🌲 **Unsupervised Anomaly Detector**: Isolation Forest profiling structural transmission anomalies.
- 🛡️ **Forensic RFC 5322 Email Parser**: Multi-hop Received headers, sender/recipient metadata, body text/HTML, and multipart attachments.
- 🔍 **Header Forensics & Impersonation Engine**: Uncovers Reply-To domain discrepancies, Return-Path divergences, and display-name spoofing.
- 🔐 **Authentication Signals Evaluation**: Audits SPF, DKIM, and DMARC headers with technically cautious explanations.
- 🌐 **Relay Path Chronology & Geo Map**: Reconstructs the complete transmission chain on an interactive Leaflet map.
- 🎯 **Lookalike Domain Detector**: Catches typosquatting against major institutions (SBI, HDFC, ICICI, Microsoft, Google, PayPal, Apple, Amazon).
- 🕸️ **Attack & Infrastructure Graph**: Interactive React Flow topology linking Email, Senders, Domains, IPs, ASNs, and URLs.
- 🔒 **Evidence Chain of Custody**: Cryptographic SHA-256 and MD5 checksum preservation.
- 📄 **Forensic PDF Investigation Report**: Generates official court/SOC-ready investigation reports via ReportLab.
- 🚀 **1-Click SIH Demo Mode**: Pre-loaded with synthetic test scenarios that execute offline in seconds.

---

## 🏗️ 4. System Architecture

```
                          ANVESHAKX PLATFORM
                                  │
                          Email Ingestion (.eml)
                                  │
                             EmailParser
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
 PHASE 1 FORENSICS                                  PHASE 2 AI / ML
 • Header Inconsistencies                           • TextCleaner Preprocessing
 • SPF / DKIM / DMARC Check                         • TF-IDF Vectorizer (1-2 ngrams)
 • Chronological Relay Path                         • Calibrated Logistic Regression
 • Lookalike Brand Matching                         • Social Engineering Profiler
 • Static Payload Check                             • Isolation Forest Anomaly Detector
         │                                          • Campaign Semantic Matcher
         │                                          • XAI Feature Importance
         └────────────────────────┬────────────────────────┘
                                  ▼
                        RISK FUSION ENGINE
               (50% Forensic + 30% ML + 20% Intel)
                                  │
                                  ▼
                   FINAL EXPLAINABLE THREAT SCORE
                                  │
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
   "WHY FLAGGED?"           GEO & GRAPH TOPOLOGY       CAMPAIGN CLUSTERS
 (Technical, AI, Intel)     (Leaflet & React Flow)   (Historical Similarity)
                                  │
                                  ▼
                       CASE REGISTRY & PDF REPORT
```

---

## 🚀 5. Quick Start & Execution

### Step 1: Install Dependencies
```bash
# Python dependencies
pip install -r backend/requirements.txt

# Frontend dependencies
cd frontend && npm install && cd ..
```

---

### Step 2: Train & Evaluate ML Models (Optional — Pre-trained artifacts included)
```bash
# Train classifier & anomaly detector
python -m ml.training.train_classifier
python -m ml.training.train_anomaly

# Run evaluation report
python -m ml.evaluation.evaluate
```

---

### Step 3: Start the Backend Server (Terminal 1)
```bash
python -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000 --reload
```
- **API Docs (Swagger)**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Check**: [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)

---

### Step 4: Start the Frontend SOC Dashboard (Terminal 2)
```bash
cd frontend
npm run dev
```
- **Web Dashboard**: 👉 **[http://localhost:5173](http://localhost:5173)**

---

### Step 5: Run Automated Tests
```bash
pytest backend/tests/ -v
```
*(All 27 unit & integration tests pass with 100% success).*

---

## 🧪 6. Smart India Hackathon (SIH) Golden Demo Flow (3–5 Min)

1. Open **[http://localhost:5173](http://localhost:5173)**.
2. Click **"Analyze New Email"** (or `/upload`).
3. Click the **1-Click Demo Button: "Business Email Compromise (CEO Fraud)"**.
4. Observe the synchronized multi-layer investigation:
   - **Risk Fusion Score**: **87 / 100 — CRITICAL RISK**.
   - **Formula Bar**: `Forensic (86 × 0.50) + ML (75 × 0.30) + Intel (65 × 0.20) = 87`.
   - **"Why Was This Email Flagged?" Triage Card**:
     - *Technical Evidence*: DMARC Policy Failure, SPF Fail, Reply-To Domain Mismatch.
     - *AI & Behavioral Evidence*: AI Classification `BUSINESS_EMAIL_COMPROMISE`, Urgency (97%), Financial Pressure (97%), Secrecy (98%).
     - *Threat Intelligence*: Tor / VPN Proxy Relay (`185.220.101.5`), Unregistered bounce domain.
   - **AI Threat Intelligence Tab**:
     - Class probability breakdown (BEC 55%, Credential Theft 10%, Legitimate 12%).
     - High-Impact Linguistic Features (`'wire'`, `'acquisition'`, `'confidential'`, `'executive'`).
     - Structural Anomaly Detector status.
   - **Campaign Similarity Tab**: Matched with `Executive Acquisition Wire Fraud Cluster` (24% semantic similarity).
   - **Relay Path & Leaflet Map**: Visualizes the German Tor proxy origin MTA.
   - **Interactive Attack Graph**: Explores React Flow topology connecting Email, Senders, Domains, IPs, and ASNs.
   - **Evidence Panel**: Verifies the immutable SHA-256 evidence certificate.
   - **Download Forensic PDF**: Generates the official investigation PDF including the AI/ML section.

---

## ⚖️ 7. Risk Fusion & Scoring Table

| Evidence Layer | Weight | Points | Key Signals |
|---|---|---|---|
| **Forensic Rules** | **50%** | 0 – 100 | DMARC/SPF fail, Reply-To redirect, display name spoof, double extension attachments |
| **Machine Learning** | **30%** | 0 – 100 | Calibrated multi-class Logistic Regression, Social Engineering urgency/financial density |
| **Threat Intelligence** | **20%** | 0 – 100 | Lookalike domain typosquatting, Tor/VPN proxy relay, suspicious TLDs, domain age |

---

## 📄 Documentation Directory

- [`docs/ML_ARCHITECTURE.md`](docs/ML_ARCHITECTURE.md): Complete Phase 2 ML design and explainability guide.
- [`docs/TRAINING.md`](docs/TRAINING.md): Dataset preparation, model training, and evaluation scripts.
- [`docs/architecture.md`](docs/architecture.md): Full platform component diagram and data pipeline.
- [`docs/threat_scoring.md`](docs/threat_scoring.md): Risk scoring formulas and threshold ranges.
- [`docs/api.md`](docs/api.md): REST API v1 specification.
- [`frontend/README.md`](frontend/README.md): React + Vite frontend documentation.
- [`backend/README.md`](backend/README.md): FastAPI backend services documentation.
- [`RUN_GUIDE.md`](RUN_GUIDE.md): Fast 2-terminal start cheat sheet.

---

## 🔒 8. Security & Forensic Integrity Principles

1. **No Execution of Untrusted Payloads**: Attachments and URLs are parsed and hashed statically; executable code is never executed.
2. **Untrusted Input Sanitization**: HTML email bodies are sanitized to strip scripts and tracking beacons.
3. **Cryptographic Chain of Custody**: Raw `.eml` files are hashed with SHA-256 immediately upon ingest and stored immutably.
4. **Appropriate Terminology**: Geolocations represent network infrastructure (MTAs / relays) and are clearly marked as approximate.
5. **Deterministic Foundation + Transparent AI**: Every score, flag, and ML prediction is explainable with feature attribution.

---

