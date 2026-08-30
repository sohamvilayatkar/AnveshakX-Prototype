# AnveshakX Architecture Documentation

## Overview
AnveshakX is structured as a decoupled two-tier system:
1. **Frontend**: React 18 single-page application built with Vite and Tailwind CSS.
2. **Backend**: Python 3.11+ asynchronous service powered by FastAPI, SQLAlchemy, and SQLite.

---

## Component Architecture

```
anveshakx/
├── backend/
│   ├── app/
│   │   ├── api/             # REST Routers (Analysis, Cases, Health, Reports)
│   │   ├── models/          # SQLAlchemy ORM schemas
│   │   ├── schemas/         # Pydantic v2 data transfer models
│   │   ├── services/        # Domain forensics & intelligence engines
│   │   └── utils/           # Utility helpers (IP, Domain, Hashing, Validation)
│   └── tests/               # Pytest automated test suite
├── frontend/
│   ├── src/
│   │   ├── components/      # Common, Layout, Graph, Map, Dashboard widgets
│   │   ├── pages/           # Dashboard, Upload, Analysis, Cases, Reports
│   │   └── services/        # Axios API client
└── sample_emails/           # Synthetic attack datasets
```

---

## Data Pipeline
1. **Ingestion**: Raw `.eml` bytes received via `POST /api/v1/analyze/upload`.
2. **Hashing**: SHA-256 and MD5 computed immediately before parsing.
3. **Parsing**: `EmailParser` processes RFC 5322 structure and multipart payloads.
4. **Analysis Services**:
   - `HeaderAnalyzer` checks Reply-To, Return-Path, Display Names.
   - `AuthenticationAnalyzer` evaluates SPF/DKIM/DMARC status.
   - `RelayAnalyzer` reconstructs chronological MTA transmission hops.
   - `IPIntelligenceService` correlates ASNs, ISPs, and coordinates.
   - `DomainAnalyzer` & `ImpersonationDetector` identify lookalikes.
   - `IndicatorExtractor` standardizes IOCs.
   - `RuleEngine` evaluates deterministic threat triggers.
   - `RiskEngine` calculates explainable 0–100 score.
   - `GraphService` produces NetworkX node-edge relationships.
5. **Persistence**: Case and Email metadata saved in SQLite.
6. **Reporting**: `ReportService` generates official PDF via ReportLab.
