# AnveshakX Phase 2 — AI/ML Architecture & Threat Intelligence

## 1. Architectural Philosophy
Phase 1 establishes the deterministic cyber forensic foundation (headers, SPF/DKIM/DMARC, hops, lookalikes, static hashes).
Phase 2 introduces an explainable, CPU-friendly machine learning and behavioral intelligence layer that answers:

> *"What linguistic, behavioral, and contextual patterns indicate that this email is likely malicious?"*

The system combines all evidence using a multi-layer Risk Fusion Engine:

$$\text{Final Threat Score} = (0.50 \times S_{\text{forensic}}) + (0.30 \times S_{\text{ml}}) + (0.20 \times S_{\text{intel}})$$

---

## 2. Pipeline Overview

```
                          INGESTED EMAIL (.eml)
                                    │
                             EmailParser
                                    │
         ┌──────────────────────────┴──────────────────────────┐
         ▼                                                     ▼
 PHASE 1 FORENSICS                                      PHASE 2 AI/ML
 • Header Inconsistencies                               • TextCleaner Preprocessing
 • SPF / DKIM / DMARC Check                             • TF-IDF Vectorizer (1-2 ngrams)
 • Chronological Relay Path                             • Calibrated Logistic Regression
 • Lookalike Brand Matching                             • Social Engineering Profiler (7 Dims)
 • Static Payload Hashing                               • Isolation Forest Anomaly Detector
         │                                              • Campaign Semantic Matcher
         │                                              • XAI Feature Importance
         └──────────────────────────┬──────────────────────────┘
                                    ▼
                          RISK FUSION ENGINE
                                    │
                                    ▼
                     FINAL EXPLAINABLE THREAT SCORE
                        (0–100 Normalized Scale)
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         ▼                          ▼                          ▼
   "WHY FLAGGED?"             GEO & GRAPH TOPOLOGY        SIMILAR CAMPAIGNS
 (Technical, AI, Intel)       (Leaflet & React Flow)     (Historical Cluster)
                                    │
                                    ▼
                         FORENSIC PDF REPORT & DB
```

---

## 3. Core AI/ML Components

### A. Primary Classifier (`ml/inference/classifier_service.py`)
- **Algorithm**: Sublinear TF-IDF (1–2 ngrams, English stop words removed) + Calibrated Multi-Class Logistic Regression.
- **Classes**:
  - `legitimate`
  - `phishing`
  - `bec` (Business Email Compromise)
  - `credential_theft`
  - `financial_fraud`
- **Output**: Predicted class, calibrated confidence (0.00–1.00), multi-class probabilities dictionary, and XAI feature importance tokens.
- **Model Version**: `anveshakx-email-classifier-v2.0`

### B. Social Engineering Profiler (`ml/inference/social_engineering.py`)
Measures 7 psychological manipulation dimensions on a 0.00–1.00 (0%–100%) scale:
1. **Urgency**: Artificial deadlines and panic triggers (`immediately`, `within 24 hours`, `without delay`, `cutoff`).
2. **Financial Pressure**: Wire transfer, bank account, and invoice settlement solicitation (`wire`, `payment`, `escrow`, `beneficiary`).
3. **Authority Impersonation**: C-suite executive, director, legal counsel pretext (`ceo`, `managing director`, `president`).
4. **Fear / Coercion**: Account suspension, legal penalty, or security lockout threats (`suspended`, `unauthorized`, `termination`).
5. **Secrecy / Isolation**: Directives to avoid phone contact or disclosure (`confidential`, `do not call`, `between us`).
6. **Credential Request**: Password, MFA token, or SSO re-verification requests (`verify password`, `authenticator code`, `login`).
7. **Call to Action**: Urgent link click or action mandates (`click here`, `reply directly`, `verify now`).

### C. Structural Anomaly Detector (`ml/inference/anomaly_detector.py`)
- **Algorithm**: Unsupervised `IsolationForest` detecting anomalous structural profiles across text length, URL count, attachment density, recipient volume, and relay hop counts.

### D. Campaign & Historical Case Correlation (`ml/inference/campaign_similarity.py`)
- Computes cosine similarity against known threat campaign signatures and stored database cases to identify cluster patterns.

### E. Explainable AI (XAI) Attribution (`ml/explainability/feature_importance.py`)
- Multiplies TF-IDF word vectors by model class coefficients to isolate the exact keywords (e.g. `'wire'`, `'confidential'`, `'acquisition'`) that drove the classification.

---

## 4. Multi-Layer Risk Fusion Formula

| Evidence Layer | Default Weight | Key Data Points |
|---|---|---|
| **Phase 1 Forensic Evidence** | **50% (0.50)** | DMARC/SPF/DKIM failures, Reply-To mismatches, Display-Name spoofing, Double-extension payloads |
| **Phase 2 AI/ML Predictions** | **30% (0.30)** | TF-IDF Logistic Regression confidence, Social Engineering urgency/financial density |
| **Threat Intelligence** | **20% (0.20)** | Lookalike typosquatting domains, Tor/VPN proxy relays, Suspicious TLDs, Fresh WHOIS domains |

### Severity Scale:
- **0 – 29: LOW (BENIGN)**
- **30 – 59: MEDIUM (ANOMALY / SUSPICIOUS)**
- **60 – 79: HIGH (PHISHING / MALWARE RISK)**
- **80 – 100: CRITICAL (BEC / ACTIVE INTRUSION)**
