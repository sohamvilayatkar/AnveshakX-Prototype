from typing import List, Dict, Any
from app.schemas.analysis import ThreatAssessment, RiskFactor


class RiskEngine:
    """
    Centralized Explainable Risk Engine:
    Calculates deterministic 0–100 threat score, categorizes threat severity,
    and assigns an explainable classification with full forensic attribution.
    """

    @classmethod
    def calculate_score(cls, rule_evaluation: Dict[str, Any]) -> ThreatAssessment:
        factors: List[RiskFactor] = rule_evaluation.get("factors", [])
        categories: Dict[str, int] = rule_evaluation.get("categories", {})

        raw_score = sum(f.points for f in factors)
        # Cap score between 0 and 100
        final_score = min(max(raw_score, 0), 100)

        # Determine Severity
        if final_score >= 80:
            severity = "CRITICAL"
        elif final_score >= 60:
            severity = "HIGH"
        elif final_score >= 30:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Determine Classification
        if final_score < 30:
            classification = "BENIGN"
            confidence = 0.95
            summary = "Email headers, authentication, and content align with legitimate organizational communication standards."
        else:
            # Rank categories by highest trigger count
            sorted_cats = sorted(categories.items(), key=lambda x: x[1], reverse=True)
            top_cat = sorted_cats[0][0] if sorted_cats else "SUSPICIOUS"

            if top_cat == "BEC":
                classification = "BUSINESS_EMAIL_COMPROMISE"
                confidence = 0.89
                summary = "Critical BEC signals identified: Executive impersonation, Reply-To redirection, and high-pressure financial transfer solicitation."
            elif top_cat == "PHISHING":
                classification = "CREDENTIAL_PHISHING"
                confidence = 0.91
                summary = "Phishing attack detected: Deceptive security alerts combined with credential harvesting links and urgency triggers."
            elif top_cat == "BRAND_IMPERSONATION":
                classification = "BRAND_IMPERSONATION"
                confidence = 0.93
                summary = "Lookalike domain and brand spoofing detected: Sender infrastructure mimics a protected institution."
            elif top_cat == "MALICIOUS_ATTACHMENT":
                classification = "SUSPICIOUS_PAYLOAD"
                confidence = 0.94
                summary = "Dangerous attachment identified: Double extension or executable script disguised as legitimate document."
            else:
                classification = "SUSPICIOUS_AUTHENTICATION_ANOMALY"
                confidence = 0.80
                summary = "Multiple authentication and transmission anomalies observed without explicit payload."

        return ThreatAssessment(
            score=final_score,
            severity=severity,
            classification=classification,
            confidence=confidence,
            summary=summary,
            factors=factors
        )
