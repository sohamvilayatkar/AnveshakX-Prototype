import re
from typing import List, Dict, Any
from app.schemas.analysis import ParsedEmailData, HeaderFinding, RiskFactor
from app.schemas.intelligence import DomainIntelligenceData, IPIntelligenceData


class RuleEngine:
    """
    Deterministic Threat Rule Engine:
    Evaluates rule-based cybersecurity triggers for BEC, Phishing,
    Brand Impersonation, Credential Theft, and Payment Diversion without ML.
    """

    @classmethod
    def evaluate(
        cls,
        email_data: ParsedEmailData,
        header_findings: List[HeaderFinding],
        domain_intel: List[DomainIntelligenceData],
        ip_intel: List[IPIntelligenceData]
    ) -> Dict[str, Any]:
        risk_factors: List[RiskFactor] = []
        triggered_categories: Dict[str, int] = {
            "BEC": 0,
            "PHISHING": 0,
            "BRAND_IMPERSONATION": 0,
            "MALICIOUS_ATTACHMENT": 0,
            "AUTH_FAILURE": 0
        }

        body_full = f"{email_data.subject} {email_data.body_text}".lower()

        # 1. Authentication Failure Rules
        auth = email_data.authentication
        if auth.dmarc_result == "FAIL":
            risk_factors.append(RiskFactor(
                name="DMARC Policy Failure",
                points=20,
                severity="CRITICAL",
                explanation="DMARC authentication check failed, indicating unverified or spoofed sender identity."
            ))
            triggered_categories["AUTH_FAILURE"] += 2
        if auth.spf_result in ("FAIL", "SOFTFAIL"):
            pts = 15 if auth.spf_result == "FAIL" else 8
            risk_factors.append(RiskFactor(
                name=f"SPF {auth.spf_result.title()}",
                points=pts,
                severity="HIGH" if pts == 15 else "MEDIUM",
                explanation=f"Sender IP was not authorized in SPF DNS records for {email_data.sender.domain or 'sender'}."
            ))
            triggered_categories["AUTH_FAILURE"] += 1
        if auth.dkim_result == "FAIL":
            risk_factors.append(RiskFactor(
                name="DKIM Verification Failure",
                points=10,
                severity="HIGH",
                explanation="Cryptographic DKIM signature verification failed."
            ))
            triggered_categories["AUTH_FAILURE"] += 1

        # 2. Header & Identity Anomaly Rules
        for f in header_findings:
            if f.type == "REPLY_TO_MISMATCH":
                risk_factors.append(RiskFactor(
                    name="Reply-To Domain Mismatch",
                    points=15,
                    severity="HIGH",
                    explanation="Responses are directed to an external mailbox differing from the sender."
                ))
                triggered_categories["BEC"] += 2
            elif f.type == "RETURN_PATH_MISMATCH":
                risk_factors.append(RiskFactor(
                    name="Return-Path Domain Mismatch",
                    points=8,
                    severity="MEDIUM",
                    explanation="Envelope bounce address domain differs from header From domain."
                ))
            elif f.type == "DISPLAY_NAME_SPOOF":
                risk_factors.append(RiskFactor(
                    name="Display Name Address Spoofing",
                    points=15,
                    severity="HIGH",
                    explanation="Display name embeds an unauthorized address to deceive the recipient."
                ))
                triggered_categories["PHISHING"] += 2

        # 3. Lookalike / Brand Impersonation Rules
        for d in domain_intel:
            if d.lookalike_detected:
                risk_factors.append(RiskFactor(
                    name=f"Brand Lookalike Domain ({d.target_brand})",
                    points=18,
                    severity="CRITICAL",
                    explanation=f"Domain '{d.domain}' mimics protected brand '{d.target_brand}' via typosquatting/combisquatting."
                ))
                triggered_categories["BRAND_IMPERSONATION"] += 3
            elif d.is_suspicious_tld:
                risk_factors.append(RiskFactor(
                    name=f"Suspicious Top-Level Domain (.{d.tld})",
                    points=8,
                    severity="MEDIUM",
                    explanation=f"Domain '{d.domain}' utilizes a TLD with high historical abuse prevalence."
                ))

        # 4. URL Heuristic Rules
        for u in email_data.urls:
            if u.has_ip_host:
                risk_factors.append(RiskFactor(
                    name="IP-Based Direct URL Host",
                    points=12,
                    severity="HIGH",
                    explanation=f"URL '{u.url}' uses a raw numerical IP address instead of a registered domain hostname."
                ))
                triggered_categories["PHISHING"] += 2
            if u.has_suspicious_keywords and len(u.suspicious_keywords) >= 2:
                risk_factors.append(RiskFactor(
                    name="Suspicious Keyword Payload in URL",
                    points=10,
                    severity="HIGH",
                    explanation=f"URL targets credential actions: {', '.join(u.suspicious_keywords)}."
                ))
                triggered_categories["PHISHING"] += 2

        # 5. Attachment Rules
        for att in email_data.attachments:
            if att.is_suspicious:
                risk_factors.append(RiskFactor(
                    name=f"Potentially Dangerous Attachment ({att.filename})",
                    points=20,
                    severity="CRITICAL",
                    explanation=f"Attachment '{att.filename}' carries high-risk executable script or double extension payload."
                ))
                triggered_categories["MALICIOUS_ATTACHMENT"] += 3

        # 6. Content / Linguistic Pretexting Rules (Deterministic keyword patterns)
        # BEC / Financial Diversion patterns
        payment_keywords = ["wire", "payment", "bank account", "beneficiary", "transfer", "invoice", "remittance", "routing number"]
        matched_payment = [w for w in payment_keywords if w in body_full]
        if len(matched_payment) >= 2:
            risk_factors.append(RiskFactor(
                name="Financial Transaction / Wire Pretext",
                points=10,
                severity="MEDIUM",
                explanation=f"Content solicits urgent financial transactions: {', '.join(matched_payment)}."
            ))
            triggered_categories["BEC"] += 2

        # Executive Authority / Secrecy language
        urgency_keywords = ["urgent", "confidential", "restricted", "do not call", "strictly confidential", "acquisition", "time-sensitive", "without delay"]
        matched_urgency = [w for w in urgency_keywords if w in body_full]
        if len(matched_urgency) >= 2:
            risk_factors.append(RiskFactor(
                name="Urgency & Confidentiality Pressure Tactics",
                points=8,
                severity="MEDIUM",
                explanation=f"Linguistic indicators of pressure tactics: {', '.join(matched_urgency)}."
            ))
            triggered_categories["BEC"] += 1

        # Phishing / Credential harvesting pretext
        cred_keywords = ["suspended", "verify your account", "unauthorized login", "password reset", "deactivation", "restricted access", "24 hours"]
        matched_cred = [w for w in cred_keywords if w in body_full]
        if len(matched_cred) >= 2:
            risk_factors.append(RiskFactor(
                name="Account Suspension & Credential Harvesting Pretext",
                points=10,
                severity="HIGH",
                explanation=f"Content simulates security urgency to coerce credential verification: {', '.join(matched_cred)}."
            ))
            triggered_categories["PHISHING"] += 2

        # 7. Anonymous / Proxy Source IP
        for ip_data in ip_intel:
            if ip_data.is_hosting and ip_data.is_proxy_vpn:
                risk_factors.append(RiskFactor(
                    name=f"Proxy / Tor Infrastructure Source ({ip_data.ip})",
                    points=8,
                    severity="MEDIUM",
                    explanation=f"Earliest visible MTA node {ip_data.ip} is associated with anonymization/proxy networks."
                ))
                break

        return {
            "factors": risk_factors,
            "categories": triggered_categories
        }
