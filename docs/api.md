# AnveshakX REST API Specification

Base URL: `http://localhost:8000/api/v1`

---

## 1. System Health
### `GET /health`
Returns system operational state and provider capabilities.
```json
{
  "status": "healthy",
  "app_name": "AnveshakX",
  "version": "1.0.0",
  "environment": "development",
  "timestamp": "2026-08-30T15:00:00Z",
  "database": "healthy",
  "capabilities": {
    "ml_engine": false,
    "ip_intelligence": true,
    "domain_intelligence": false
  }
}
```

---

## 2. Analysis Endpoints

### `POST /analyze/upload`
Uploads raw `.eml` multipart file.
- **Content-Type**: `multipart/form-data`
- **Body**: `file: <binary>`
- **Response**: `AnalysisResponse` object containing case, parsed email, threat assessment, header findings, relay hops, IP intelligence, URLs, attachments, IOCs, and relationship graph.

### `POST /analyze/sample/{sample_name}`
Executes analysis on a bundled demo sample (`bec`, `phishing`, `impersonation`, `legitimate`).

### `GET /analyze/case/{case_id}`
Retrieves the full forensic analysis for an existing stored case.

---

## 3. Case Management Endpoints

### `GET /cases`
List stored cases.
- **Query Parameters**:
  - `skip`: int (default 0)
  - `limit`: int (default 50)
  - `severity`: string (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)

### `GET /cases/{case_id}`
Retrieve individual case record.

### `PATCH /cases/{case_id}`
Update case status or analyst notes.

### `DELETE /cases/{case_id}`
Delete case and associated evidence records.

---

## 4. Report Endpoints

### `GET /reports/{case_id}/pdf`
Generates and serves the official court/SOC-ready Forensic PDF Investigation Report via ReportLab.
