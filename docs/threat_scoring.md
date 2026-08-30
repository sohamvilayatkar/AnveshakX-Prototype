# Threat Scoring Methodology

AnveshakX uses a deterministic, explainable scoring engine designed to avoid opaque black-box decisions.

---

## Score Range & Severity Levels

| Threat Score | Severity Level | Typical Classification | Action Required |
|---|---|---|---|
| **0 – 29** | **LOW** | `BENIGN` | No action required. Standard legitimate communication. |
| **30 – 59** | **MEDIUM** | `SUSPICIOUS_ANOMALY` | Review identity and domain discrepancies. |
| **60 – 79** | **HIGH** | `CREDENTIAL_PHISHING` / `MALWARE` | Quarantine message and block originating MTA/URLs. |
| **80 – 100** | **CRITICAL** | `BUSINESS_EMAIL_COMPROMISE` | Immediate incident escalation, alert finance & security teams. |

---

## Weighted Risk Factors

Every point assigned to an email corresponds to a verifiable technical anomaly:

1. **Authentication Failures**:
   - `DMARC Policy Failure`: **+20 pts**
   - `SPF Failure`: **+15 pts**
   - `DKIM Verification Failure`: **+10 pts**
   - `SPF Softfail`: **+8 pts**

2. **Identity & Header Inconsistencies**:
   - `Reply-To Domain Mismatch`: **+15 pts**
   - `Display Name Address Spoofing`: **+15 pts**
   - `Return-Path Domain Mismatch`: **+8 pts**
   - `Message-ID Domain Discrepancy`: **+5 pts**

3. **Domain & Brand Pretexting**:
   - `Brand Lookalike Domain`: **+18 pts**
   - `Suspicious Top-Level Domain`: **+8 pts**

4. **Payload & URL Heuristics**:
   - `Dangerous / Double Extension Attachment`: **+20 pts**
   - `IP-Based URL Host`: **+12 pts**
   - `Suspicious Keyword-Dense URL`: **+10 pts**

5. **Linguistic Pretexting Triggers**:
   - `Urgent Financial Transfer / Wire Pretext`: **+10 pts**
   - `Account Suspension / Credential Harvest`: **+10 pts**
   - `Confidentiality & Secrecy Pressure`: **+8 pts**
