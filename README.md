# AnveshakX (अन्वेषक-X)

> **AI-ready Email Threat Detection, Geolocation & Forensic Intelligence Platform**  
> *Smart India Hackathon (SIH) Prototype — Phase 1 (Deterministic Forensics Engine)*

---

## 📌 1. Problem Statement

Email remains the primary initial attack vector in over 90% of cyber breaches, including **Business Email Compromise (BEC)**, **Executive Impersonation**, and **Targeted Credential Harvesting**. 

Traditional spam filters operate as black-box classifiers that label messages as "spam" or "ham" without providing explainable evidence. When a high-impact incident occurs, SOC analysts and digital forensics investigators must manually:
- Parse raw headers and extract multi-hop Received lines.
- Map mail transfer agent (MTA) relays across international networks.
- Determine whether SPF/DKIM/DMARC authentication anomalies represent spoofing.
- Correlate lookalike domains and typosquatted brands.
- Preserve chain of custody with cryptographic integrity checksums.

This manual process is slow, error-prone, and delays critical incident response during active wire-fraud attempts or executive account takeovers.

---

## 💡 2. Solution: AnveshakX

**AnveshakX** is a specialized cyber forensic intelligence platform that converts an untrusted, raw `.eml` email into structured, explainable, and visually intuitive digital evidence.

AnveshakX is **NOT merely an email spam classifier**. Its core purpose is to answer critical forensic questions:
- **Who does the email claim to be from?** (Display name vs envelope consistency)
- **Is that identity technically consistent?** (Reply-To / Return-Path redirection)
- **What authentication signals are present?** (SPF, DKIM, DMARC validation)
- **Through which mail servers did the email travel?** (Chronological MTA relay hops)
- **What is the earliest reliable source infrastructure?** (Earliest visible public IP)
- **Where is that infrastructure geolocated?** (Autonomous System, ISP, country, city, coordinates)
- **Which URLs and domains are suspicious?** (Levenshtein lookalike brand matching, entropy)
- **Why was the final threat score assigned?** (Explainable 0–100 weighted factor breakdown)
- **How is evidence preserved?** (SHA-256 and MD5 cryptographic integrity records)

---

## ⚡ 3. Key Features

- 🛡️ **Forensic Email Parser**: Resilient RFC 5322 parsing that never crashes on malformed headers, extracting senders, recipients, body text/HTML, and multipart attachments.
- 🔍 **Header Forensics & Identity Anomaly Detection**: Uncovers Reply-To domain discrepancies, Return-Path divergences, and display-name spoofing.
- 🔐 **Authentication Signals Evaluation**: Audits SPF, DKIM, and DMARC headers with technically cautious explanations.
- 🌐 **Relay Path Chronology**: Reconstructs the complete transmission chain from origin MTA to recipient mailbox.
- 📍 **IP Intelligence & Geolocation**: Identifies hosting providers, ASNs, Tor/VPN/proxy nodes, and plots relays on an interactive Leaflet map.
- 🎯 **Lookalike Domain & Brand Impersonation Detector**: Uses Levenshtein distance and token similarity algorithms to catch typosquatting against major institutions (SBI, HDFC, ICICI, Microsoft, Google, PayPal, Apple, Amazon).
- 🔗 **URL & Payload Analyzer**: Evaluates URL entropy, IP-based hosts, dangerous attachment extensions, and double extensions (`invoice.pdf.exe`).
- 📊 **Explainable 0–100 Risk Engine**: Transparent scoring formula with clear point attribution (0–29 Low, 30–59 Medium, 60–79 High, 80–100 Critical).
- 🕸️ **Attack & Infrastructure Graph**: Generates interactive relationship topologies using NetworkX and React Flow.
- 🔒 **Evidence Chain of Custody**: Immediate SHA-256 and MD5 hashing of raw emails and attachments with immutable evidence preservation.
- 📄 **Forensic PDF Investigation Report**: Generates court/SOC-ready PDF forensic investigation reports via ReportLab.
- 🚀 **1-Click SIH Demo Mode**: Pre-loaded with synthetic test scenarios (BEC, Phishing, Impersonation, Legitimate) that execute offline in seconds.

---

## 🏗️ 4. System Architecture

```
                                  ANVESHAKX PLATFORM
                                          │
                  ┌───────────────────────┴───────────────────────┐
                  ▼                                               ▼
          FRONTEND (React + Vite)                         BACKEND (FastAPI)
  ┌───────────────────────────────┐               ┌───────────────────────────────┐
  │ • SOC Threat Dashboard        │               │ • REST API Endpoints (/v1)    │
  │ • Forensic Investigation View │  HTTP/JSON    │ • Forensic Email Parser       │
  │ • React Flow Attack Graph     │ ◄───────────► │ • Header & Auth Analyzer      │
  │ • Leaflet Geolocation Map     │               │ • Relay Path Reconstructor    │
  │ • IOC & Evidence Tables       │               │ • Lookalike Domain Engine     │
  │ • PDF Report Viewer           │               │ • Deterministic Rule Engine   │
  └───────────────────────────────┘               │ • Explainable Risk Engine     │
                                                  │ • NetworkX Graph Generator    │
                                                  │ • ReportLab PDF Service       │
                                                  └───────────────┬───────────────┘
                                                                  ▼
                                                          SQLite Database &
                                                      Immutable Evidence Store
```

---

## 🛠️ 5. Technology Stack

### Backend
- **Python**: 3.11+
- **API Framework**: FastAPI & Uvicorn
- **Validation**: Pydantic v2 & Pydantic-Settings
- **Database**: SQLite & SQLAlchemy ORM
- **Forensic Parsing**: Python `email`, BeautifulSoup4, `tldextract`, `dnspython`, `dateutil`
- **Graph & Reporting**: NetworkX, ReportLab
- **Testing**: Pytest, Pytest-Asyncio

### Frontend
- **Framework**: React 18 & Vite
- **Styling**: Tailwind CSS (SOC Dark Cybersecurity Theme)
- **Graph Visualization**: React Flow (`reactflow`)
- **Map Geolocation**: Leaflet & React-Leaflet
- **Analytics Charts**: Recharts
- **Icons**: Lucide React
- **API Client**: Axios

---

## 🚀 6. Installation & How to Run

### Prerequisites
- **Python**: 3.11 or newer
- **Node.js**: v18 or newer
- **Git**

---

### Step 1: Clone Repository & Setup Backend

```bash
# Navigate to project root
cd AnveshakX

# Install Python dependencies
pip install -r backend/requirements.txt

# (Optional) Copy environment variables
cp .env.example .env
```

---

### Step 2: Start the FastAPI Backend Server

```bash
python -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000 --reload
```

Backend Services available at:
- **API Root**: [http://localhost:8000](http://localhost:8000)
- **Interactive Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Check**: [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)

---

### Step 3: Start the React Frontend Application

Open a second terminal window:

```bash
cd frontend
npm install
npm run dev
```

Frontend SOC Dashboard available at:
- **Web Dashboard**: [http://localhost:5173](http://localhost:5173)

---

### Step 4: Run Automated Tests

```bash
pytest backend/tests/ -v
```

---

## 🧪 7. Smart India Hackathon (SIH) Demo Flow (3–5 Min)

1. Open **[http://localhost:5173](http://localhost:5173)** in your browser.
2. Click **"Analyze New Email"** or go to the `/upload` tab.
3. Click on the **1-Click Demo Scenario: "Business Email Compromise (CEO Fraud)"**.
4. Observe the forensic analysis execution:
   - **Threat Score**: Gauge displays **91 / 100 — CRITICAL RISK**.
   - **Classification**: Identified as `BUSINESS_EMAIL_COMPROMISE`.
   - **Header Forensics**: Reply-To mismatch detected (`fast-offshore-transfers.net` vs `globalenterprise-corp.com`).
   - **Authentication**: Shows SPF FAIL and DMARC FAIL.
   - **Relay Path**: Hop 1 identified at `185.220.101.5` with transit protocols.
   - **Geo Map**: Leaflet map highlights the German Tor/proxy hosting node.
   - **Attack Graph**: React Flow renders the interactive entity relationship graph.
   - **Evidence Panel**: Verifies the immutable SHA-256 evidence hash.
   - **Download PDF**: Click **"Forensic PDF Report"** to download the court-admissible ReportLab PDF.

---

## 📡 8. API Endpoints Reference (v1)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Service root and status |
| `GET` | `/api/v1/health` | Health check, database status, engine capabilities |
| `POST` | `/api/v1/analyze/upload` | Upload `.eml` file, compute SHA-256, run full forensic pipeline |
| `POST` | `/api/v1/analyze/sample/{name}` | Load bundled demo sample (`bec`, `phishing`, `impersonation`, `legitimate`) |
| `GET` | `/api/v1/analyze/case/{case_id}` | Retrieve complete forensic analysis for an existing case |
| `GET` | `/api/v1/cases` | List stored investigation cases with pagination & filters |
| `GET` | `/api/v1/cases/{case_id}` | Retrieve specific case investigation metadata |
| `PATCH` | `/api/v1/cases/{case_id}` | Update case status or analyst notes |
| `DELETE` | `/api/v1/cases/{case_id}` | Delete case and associated evidence records |
| `GET` | `/api/v1/reports/{case_id}/status`| Check PDF report availability |
| `GET` | `/api/v1/reports/{case_id}/pdf` | Generate and download official Forensic PDF Report |

---

## ⚖️ 9. Threat Scoring Methodology

AnveshakX employs a transparent, explainable 0–100 scoring system where every point is linked to a deterministic forensic finding:

| Forensic Factor | Points | Severity | Rationale |
|---|---|---|---|
| **DMARC Failure** | +20 | CRITICAL | Direct unaligned spoofing of the sender domain |
| **Dangerous Attachment** | +20 | CRITICAL | Executable script or double extension payload (`.pdf.exe`) |
| **Brand Lookalike Domain** | +18 | CRITICAL | Typosquatting / combisquatting mimicking protected brand |
| **SPF Failure** | +15 | HIGH | Sending IP is unauthorized in domain DNS records |
| **Reply-To Mismatch** | +15 | HIGH | Response redirection to external unaligned mailbox |
| **Display Name Spoof** | +15 | HIGH | Embedding misleading address inside display name |
| **IP-Based URL Host** | +12 | HIGH | Direct numerical IP host bypassing domain reputation |
| **DKIM Failure** | +10 | HIGH | Cryptographic signature altered or invalid |
| **Credential Phishing Pretext** | +10 | HIGH | Coercive account suspension / verification language |
| **Suspicious URL Keywords** | +10 | HIGH | Multiple credential actions (`login`, `verify`, `banking`) |
| **Financial / Wire Pretext** | +10 | MEDIUM | Urgent wire transfer or beneficiary change request |
| **Return-Path Mismatch** | +8 | MEDIUM | Envelope bounce redirected to third-party |
| **Urgency / Confidentiality** | +8 | MEDIUM | Pressure tactics (`strictly confidential`, `do not call`) |
| **Suspicious TLD** | +8 | MEDIUM | High-abuse top-level domain (`.xyz`, `.top`, `.click`) |
| **Proxy / Tor Source IP** | +8 | MEDIUM | MTA relay originated from anonymized infrastructure |

### Score Thresholds:
- **0 – 29: LOW (BENIGN)**
- **30 – 59: MEDIUM (SUSPICIOUS ANOMALY)**
- **60 – 79: HIGH (PHISHING / MALWARE RISK)**
- **80 – 100: CRITICAL (BEC / ACTIVE INTRUSION)**

---

## 🔒 10. Security & Forensic Integrity Principles

1. **Strict Static Analysis**: Attachments and URLs are parsed and hashed statically; executable code is never executed.
2. **Untrusted Input Sanitization**: HTML email bodies are sanitized before rendering to eliminate script injection and tracking beacons.
3. **Cryptographic Chain of Custody**: Raw `.eml` files are hashed with SHA-256 immediately upon arrival and preserved immutably.
4. **Approximate Geolocation Disclaimer**: Geolocation reflects Mail Transfer Agent (MTA) infrastructure and does not establish physical personal identity.
5. **Deterministic Foundation**: Zero reliance on black-box predictions; every finding is backed by technical evidence.

---

## 🔮 11. Phase 2 Machine Learning Architecture

AnveshakX Phase 1 is purposefully architected for seamless Phase 2 ML integration. The `RuleBasedThreatDetector` implements a modular provider interface:

```
                      EMAIL DATA INGESTION
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
       PHASE 1 ENGINE                  PHASE 2 ENGINE
   [Deterministic Rules]          [Lightweight NLP & ML]
   • Header Inconsistencies       • Linguistic Embedding
   • SPF/DKIM/DMARC Signals       • Anomaly Classifier
   • Lookalike Edit Distance      • Header Vectorizer
               │                               │
               └───────────────┬───────────────┘
                               ▼
                      RISK FUSION ENGINE
                               │
                               ▼
               FINAL EXPLAINABLE THREAT SCORE
```

---

## 🇮🇳 12. Smart India Hackathon (SIH) Relevance

AnveshakX directly addresses critical national cybersecurity priorities:
- **Financial Fraud Mitigation**: Protects public sector banks and enterprises from wire diversion and CEO fraud.
- **Explainability for Law Enforcement**: Provides court-ready PDF forensic reports with verifiable SHA-256 evidence hashes.
- **Offline Reliability**: Operates entirely air-gapped without requiring cloud LLMs or recurring API subscriptions.
- **Indigenous Cyber Capability**: Built as an open, extensible forensic foundation aligned with India's cyber defense initiatives.

---

## 📄 License
AnveshakX is released under the **MIT License**.
