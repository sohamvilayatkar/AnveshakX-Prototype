import pytest
from pathlib import Path
from app.services import (
    EmailParser, HeaderAnalyzer, AuthenticationAnalyzer, RelayAnalyzer,
    IPIntelligenceService, DomainAnalyzer, ImpersonationDetector,
    IndicatorExtractor, RuleEngine, RiskEngine, GraphService, ReportService
)
from app.api.routes_analysis import execute_full_forensic_pipeline
from app.database import SessionLocal


def test_impersonation_detector():
    # Test SBI lookalike
    res1 = ImpersonationDetector.check_domain("sbi-secure-portal-verify.xyz")
    assert res1["is_impersonation"] is True
    assert res1["target_brand"] == "SBI"

    # Test Microsoft lookalike
    res2 = ImpersonationDetector.check_domain("micros0ft-support-portal.top")
    assert res2["is_impersonation"] is True
    assert res2["target_brand"] == "Microsoft"

    # Test exact legitimate domain
    res3 = ImpersonationDetector.check_domain("microsoft.com")
    assert res3["is_impersonation"] is False


def test_bec_full_pipeline():
    eml_path = Path(__file__).resolve().parent.parent.parent / "sample_emails" / "bec.eml"
    with open(eml_path, "rb") as f:
        raw_bytes = f.read()

    db = SessionLocal()
    try:
        analysis = execute_full_forensic_pipeline(raw_bytes, "bec.eml", "message/rfc822", db)
        assert analysis.threat.score >= 80
        assert analysis.threat.severity == "CRITICAL"
        assert analysis.threat.classification == "BUSINESS_EMAIL_COMPROMISE"
        assert len(analysis.relay_path) == 2
        assert len(analysis.header_findings) >= 2
        assert len(analysis.iocs) >= 4
        assert len(analysis.graph.nodes) >= 4
        assert len(analysis.timeline) >= 2
        
        # Test PDF Report Generation
        pdf_bytes = ReportService.generate_pdf(analysis)
        assert len(pdf_bytes) > 1000
        assert pdf_bytes.startswith(b"%PDF")
    finally:
        db.close()


def test_phishing_full_pipeline():
    eml_path = Path(__file__).resolve().parent.parent.parent / "sample_emails" / "phishing.eml"
    with open(eml_path, "rb") as f:
        raw_bytes = f.read()

    db = SessionLocal()
    try:
        analysis = execute_full_forensic_pipeline(raw_bytes, "phishing.eml", "message/rfc822", db)
        assert analysis.threat.score >= 60
        assert analysis.threat.severity in ("HIGH", "CRITICAL")
        assert any(d.lookalike_detected for d in analysis.domains)
    finally:
        db.close()


def test_legitimate_full_pipeline():
    eml_path = Path(__file__).resolve().parent.parent.parent / "sample_emails" / "legitimate.eml"
    with open(eml_path, "rb") as f:
        raw_bytes = f.read()

    db = SessionLocal()
    try:
        analysis = execute_full_forensic_pipeline(raw_bytes, "legitimate.eml", "message/rfc822", db)
        assert analysis.threat.score < 30
        assert analysis.threat.severity == "LOW"
        assert analysis.threat.classification == "BENIGN"
    finally:
        db.close()
