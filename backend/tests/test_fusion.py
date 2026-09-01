import pytest
from app.schemas.analysis import ThreatAssessment, RiskFactor
from app.services.risk_fusion import RiskFusionEngine


def test_risk_fusion_bec_critical():
    forensic = ThreatAssessment(
        score=86,
        severity="CRITICAL",
        classification="BUSINESS_EMAIL_COMPROMISE",
        confidence=0.89,
        summary="BEC indicators detected",
        factors=[
            RiskFactor(name="DMARC Policy Failure", points=20, severity="CRITICAL", explanation="DMARC failed"),
            RiskFactor(name="Reply-To Domain Mismatch", points=15, severity="HIGH", explanation="Mismatch")
        ]
    )

    ml_pred = {
        "classification": "BUSINESS_EMAIL_COMPROMISE",
        "raw_class": "bec",
        "confidence": 0.93,
        "linguistic_signals": [{"token": "wire", "weight": 0.8, "description": "Wire keyword"}],
        "status": "active"
    }

    social_eng = {"urgency": 0.91, "financial_pressure": 0.88, "authority": 0.73, "secrecy": 0.61}
    ip_intel = []
    domain_intel = []
    anomaly_res = {"is_anomaly": True, "anomaly_score": 0.82, "explanation": "Urgent wire anomaly"}

    result = RiskFusionEngine.fuse(
        forensic_assessment=forensic,
        ml_prediction=ml_pred,
        social_eng=social_eng,
        ip_intel=ip_intel,
        domain_intel=domain_intel,
        anomaly_res=anomaly_res
    )

    threat = result["threat"]
    fusion = result["fusion"]

    assert threat.score >= 80
    assert threat.severity == "CRITICAL"
    assert threat.classification == "BUSINESS_EMAIL_COMPROMISE"
    assert fusion["forensic_score"] == 86
    assert fusion["ml_score"] >= 88
    assert len(fusion["ai_evidence"]) > 0


def test_risk_fusion_legitimate():
    forensic = ThreatAssessment(
        score=0,
        severity="LOW",
        classification="BENIGN",
        confidence=0.95,
        summary="Legitimate",
        factors=[]
    )

    ml_pred = {
        "classification": "LEGITIMATE_COMMUNICATION",
        "raw_class": "legitimate",
        "confidence": 0.94,
        "linguistic_signals": [],
        "status": "active"
    }

    social_eng = {"urgency": 0.0, "financial_pressure": 0.0, "authority": 0.0, "secrecy": 0.0}

    result = RiskFusionEngine.fuse(
        forensic_assessment=forensic,
        ml_prediction=ml_pred,
        social_eng=social_eng,
        ip_intel=[],
        domain_intel=[],
        anomaly_res={"is_anomaly": False, "anomaly_score": 0.1, "explanation": "Normal"}
    )

    threat = result["threat"]
    assert threat.score < 30
    assert threat.severity == "LOW"
    assert threat.classification == "BENIGN"
