import pytest
from ml.preprocessing.text_cleaner import TextCleaner
from ml.inference.classifier_service import EmailClassifierService
from ml.inference.social_engineering import SocialEngineeringAnalyzer
from ml.inference.anomaly_detector import AnomalyDetectorService
from ml.inference.campaign_similarity import CampaignSimilarityMatcher


def test_text_cleaner():
    subject = "URGENT: Verify Your Account Password"
    body_html = "<html><body><script>alert(1)</script><p>Please click <a href='https://phish.xyz/login'>here</a> to verify.</p></body></html>"

    cleaned = TextCleaner.extract_clean_text(subject=subject, body_html=body_html)
    assert "urgent" in cleaned
    assert "password" in cleaned
    assert "verify" in cleaned
    assert "alert(1)" not in cleaned
    assert "<script>" not in cleaned


def test_ml_classifier_bec_prediction():
    subject = "URGENT & CONFIDENTIAL: Executive Wire Transfer Required"
    body = "Please wire $148,500 to our offshore acquisition bank account immediately. Do not call as I am in a closed meeting."

    res = EmailClassifierService.predict(subject=subject, body_text=body)
    assert res["status"] == "active"
    assert res["raw_class"] == "bec"
    assert res["classification"] == "BUSINESS_EMAIL_COMPROMISE"
    assert res["confidence"] > 0.70
    assert "bec" in res["probabilities"]
    assert len(res["linguistic_signals"]) > 0


def test_ml_classifier_legitimate_prediction():
    subject = "Sprint Planning and Team Backlog Review"
    body = "Hi team, let us review the sprint backlog tickets and milestone deliverables for next week on our wiki."

    res = EmailClassifierService.predict(subject=subject, body_text=body)
    assert res["raw_class"] == "legitimate"
    assert res["classification"] == "LEGITIMATE_COMMUNICATION"
    assert res["confidence"] > 0.60


def test_social_engineering_analyzer():
    subject = "URGENT: Executive Wire Transfer - Confidential"
    body = "CEO Office: Process an immediate wire payment of $95,000 to vendor escrow account before cutoff. Do not discuss."

    scores = SocialEngineeringAnalyzer.analyze(subject=subject, body_text=body)
    assert scores["urgency"] >= 0.70
    assert scores["financial_pressure"] >= 0.70
    assert scores["authority"] >= 0.40
    assert scores["secrecy"] >= 0.70


def test_anomaly_detector():
    res = AnomalyDetectorService.evaluate(
        text_len=120,
        url_count=6,
        attachment_count=2,
        recipient_count=1,
        relay_count=1,
        urgency_score=0.95,
        financial_score=0.90
    )
    assert "is_anomaly" in res
    assert "anomaly_score" in res
    assert isinstance(res["explanation"], str)


def test_campaign_similarity_matcher():
    subject = "Acquisition Wire Transfer Payment for Escrow Settlement"
    body = "Please execute the executive acquisition wire transfer to the beneficiary account immediately."

    matches = CampaignSimilarityMatcher.match_campaigns(subject=subject, body_text=body)
    assert len(matches) > 0
    assert matches[0]["similarity_score"] > 0.15
    assert "Executive" in matches[0]["campaign_name"] or "Wire" in matches[0]["campaign_name"]
