from typing import Dict, Any, List, Optional
from app.config import settings
from app.schemas.analysis import ThreatAssessment, RiskFactor


class RiskFusionEngine:
    """
    Multi-Layer Risk Fusion Engine:
    Fuses Phase 1 Forensic Evidence (50%), Phase 2 ML Predictions (30%),
    and Threat Intelligence Signals (20%) into an explainable 0–100 threat assessment.
    """

    @classmethod
    def fuse(
        cls,
        forensic_assessment: ThreatAssessment,
        ml_prediction: Dict[str, Any],
        social_eng: Dict[str, float],
        ip_intel: List[Any],
        domain_intel: List[Any],
        anomaly_res: Dict[str, Any]
    ) -> Dict[str, Any]:
        w_forensic = getattr(settings, "FORENSIC_WEIGHT", 0.50)
        w_ml = getattr(settings, "ML_WEIGHT", 0.30)
        w_intel = getattr(settings, "INTEL_WEIGHT", 0.20)

        # 1. Forensic Score from Phase 1 rules (0 - 100)
        forensic_score = float(forensic_assessment.score)

        # 2. ML Score derived from primary classifier confidence & class
        ml_class = ml_prediction.get("raw_class", "legitimate")
        ml_confidence = ml_prediction.get("confidence", 0.50)

        if ml_class == "legitimate":
            # High legitimate confidence lowers ML threat score
            ml_score = max(0.0, (1.0 - ml_confidence) * 40.0)
        else:
            # Malicious classes scale by confidence (e.g. 0.93 -> ~93 points)
            base_class_weight = {
                "bec": 95.0,
                "phishing": 90.0,
                "credential_theft": 92.0,
                "financial_fraud": 88.0
            }.get(ml_class, 80.0)
            ml_score = min(100.0, base_class_weight * ml_confidence)

        # Adjust ML score slightly if social engineering signals are exceptionally strong
        max_social_signal = max(social_eng.values()) if social_eng else 0.0
        if max_social_signal > 0.85 and ml_class != "legitimate":
            ml_score = min(100.0, ml_score + 5.0)

        # 3. Threat Intelligence Score (derived from Geo, ASN, WHOIS, Lookalikes, Relays)
        intel_points = 0.0
        # Lookalike domains
        if any(getattr(d, "lookalike_detected", False) for d in domain_intel):
            intel_points += 45.0
        elif any(getattr(d, "is_suspicious_tld", False) for d in domain_intel):
            intel_points += 25.0

        # Proxy / Tor / Bulletproof IPs
        if any(getattr(ip, "is_proxy_vpn", False) for ip in ip_intel):
            intel_points += 45.0
        elif any(getattr(ip, "is_hosting", False) for ip in ip_intel):
            intel_points += 20.0

        # Fresh / newly registered domains (< 30 days)
        if any(getattr(d, "domain_age_days", 999) < 30 for d in domain_intel):
            intel_points += 25.0

        # Domain routing / third-party unaligned redirection
        if len(domain_intel) > 1:
            intel_points += 20.0

        intel_score = min(100.0, intel_points)

        # If it is clearly legitimate in Phase 1 and ML, keep intel score 0
        if forensic_score <= 10 and ml_class == "legitimate":
            intel_score = 0.0

        # 4. Weighted Risk Fusion Calculation
        final_score_raw = (w_forensic * forensic_score) + (w_ml * ml_score) + (w_intel * intel_score)
        
        # If Forensic and ML corroborate a critical threat (e.g. BEC or Credential Phishing with high signals)
        if forensic_score >= 80 and (ml_class in ["bec", "phishing", "credential_theft"] or ml_score >= 70):
            final_score_raw = max(final_score_raw, 85.0)

        final_score = int(round(min(max(final_score_raw, 0.0), 100.0)))

        # Determine Final Unified Severity
        if final_score >= 80:
            final_severity = "CRITICAL"
        elif final_score >= 60:
            final_severity = "HIGH"
        elif final_score >= 30:
            final_severity = "MEDIUM"
        else:
            final_severity = "LOW"

        # Determine Unified Classification
        # Prioritize ML classification if confidence is high and forensic findings corroborate
        if final_score < 30:
            unified_classification = "BENIGN"
            confidence = 0.95
            summary = "Email headers, authentication, and linguistic patterns conform to legitimate communication standards."
        else:
            if ml_class == "bec" or "BUSINESS_EMAIL" in forensic_assessment.classification:
                unified_classification = "BUSINESS_EMAIL_COMPROMISE"
                confidence = max(ml_confidence, 0.88)
                summary = "Critical BEC attack detected: Executive identity pretext combined with urgent payment/wire transfer solicitation."
            elif ml_class == "phishing" or ml_class == "credential_theft":
                unified_classification = "CREDENTIAL_PHISHING"
                confidence = max(ml_confidence, 0.90)
                summary = "Phishing threat identified: Deceptive account suspension alerts and credential harvesting infrastructure."
            elif ml_class == "financial_fraud":
                unified_classification = "FINANCIAL_WIRE_FRAUD"
                confidence = max(ml_confidence, 0.87)
                summary = "Financial diversion detected: Unauthorized bank account or invoice remittance redirection."
            elif any(getattr(d, "lookalike_detected", False) for d in domain_intel):
                unified_classification = "BRAND_IMPERSONATION"
                confidence = 0.93
                summary = "Brand impersonation detected: Lookalike domain mimicking a protected enterprise."
            else:
                unified_classification = forensic_assessment.classification
                confidence = forensic_assessment.confidence
                summary = forensic_assessment.summary

        # 5. Build "Why Was This Flagged?" Categorized Tri-Pane Evidence
        technical_evidence = []
        for f in forensic_assessment.factors:
            technical_evidence.append({
                "title": f.name,
                "severity": f.severity,
                "points": f.points,
                "explanation": f.explanation
            })

        ai_evidence = []
        if ml_prediction.get("status") == "active":
            ai_evidence.append({
                "title": f"AI Threat Classification: {ml_prediction.get('classification')}",
                "severity": "CRITICAL" if ml_score >= 80 else ("HIGH" if ml_score >= 60 else "MEDIUM"),
                "points": int(round(ml_score * w_ml)),
                "explanation": f"Statistical text classification model assigned {int(ml_confidence * 100)}% confidence."
            })

        for signal in ml_prediction.get("linguistic_signals", []):
            ai_evidence.append({
                "title": f"High-Impact Keyword: '{signal['token']}'",
                "severity": "MEDIUM",
                "points": int(signal.get("weight", 1) * 5),
                "explanation": signal.get("description", "")
            })

        for dim, val in social_eng.items():
            if val >= 0.70:
                dim_label = dim.replace("_", " ").title()
                ai_evidence.append({
                    "title": f"Social Engineering: High {dim_label} ({int(val * 100)}%)",
                    "severity": "HIGH" if val >= 0.85 else "MEDIUM",
                    "points": int(val * 10),
                    "explanation": f"Linguistic density analysis detected elevated {dim_label.lower()} manipulation tactics."
                })

        intel_evidence = []
        for d in domain_intel:
            if getattr(d, "lookalike_detected", False):
                intel_evidence.append({
                    "title": f"Lookalike Domain: {d.domain}",
                    "severity": "CRITICAL",
                    "points": 25,
                    "explanation": f"Domain mimics protected brand '{getattr(d, 'target_brand', 'organization')}'."
                })
            elif getattr(d, "is_suspicious_tld", False):
                intel_evidence.append({
                    "title": f"Suspicious TLD (.{getattr(d, 'tld', 'ext')})",
                    "severity": "MEDIUM",
                    "points": 10,
                    "explanation": f"Domain '{d.domain}' uses high-risk top-level domain."
                })

        for ip in ip_intel:
            if getattr(ip, "is_proxy_vpn", False):
                intel_evidence.append({
                    "title": f"Tor / VPN Proxy Relay ({ip.ip})",
                    "severity": "HIGH",
                    "points": 20,
                    "explanation": f"Relay node {ip.ip} ({getattr(ip, 'organization', 'Proxy')}) is an anonymization endpoint."
                })

        # Top 5 unified factors
        top_factors = [
            f["title"] for f in (technical_evidence[:3] + ai_evidence[:3] + intel_evidence[:2])
        ][:6]

        fusion_breakdown = {
            "forensic_score": int(round(forensic_score)),
            "forensic_weight": w_forensic,
            "ml_score": int(round(ml_score)),
            "ml_weight": w_ml,
            "intel_score": int(round(intel_score)),
            "intel_weight": w_intel,
            "final_score": final_score,
            "formula": f"Final ({final_score}) = ({forensic_score:.0f} × {w_forensic}) + ({ml_score:.0f} × {w_ml}) + ({intel_score:.0f} × {w_intel})",
            "technical_evidence": technical_evidence,
            "ai_evidence": ai_evidence,
            "intel_evidence": intel_evidence,
            "top_factors": top_factors
        }

        threat_unified = ThreatAssessment(
            score=final_score,
            severity=final_severity,
            classification=unified_classification,
            confidence=confidence,
            summary=summary,
            factors=forensic_assessment.factors
        )

        return {
            "threat": threat_unified,
            "fusion": fusion_breakdown
        }
