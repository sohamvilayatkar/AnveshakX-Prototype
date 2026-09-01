from typing import Dict, Any
from ml.preprocessing.text_cleaner import TextCleaner


class SocialEngineeringAnalyzer:
    """
    Social Engineering Signal Detector:
    Measures 7 behavioral and psychological manipulation dimensions in email text:
    - Urgency
    - Authority Impersonation
    - Financial Pressure
    - Fear / Coercion
    - Secrecy / Isolation
    - Credential Request
    - Call to Action
    """

    LEXICONS = {
        "urgency": [
            "urgent", "immediate", "immediately", "without delay", "time sensitive", "time-sensitive",
            "asap", "deadline", "today", "cutoff", "within 24 hours", "within 12 hours", "within 6 hours",
            "critical notice", "promptly", "hurry", "expires today", "before close of business"
        ],
        "authority": [
            "ceo", "chief executive", "managing director", "president", "director", "cfo",
            "chief financial", "executive board", "board of directors", "legal counsel",
            "office of the ceo", "it support desk", "security center", "administrator"
        ],
        "financial_pressure": [
            "wire", "wire transfer", "payment", "bank account", "beneficiary", "invoice",
            "settlement", "acquisition", "funds", "direct deposit", "remittance", "routing number",
            "swift", "iban", "$", "dollar", "escrow", "overdue balance", "consulting fees"
        ],
        "fear": [
            "suspended", "suspension", "termination", "account locked", "deactivated",
            "unauthorized login", "compromised", "penalty", "late interest", "legal action",
            "permanent lockout", "restricted access", "breach detected"
        ],
        "secrecy": [
            "confidential", "strictly confidential", "restricted phone", "do not call",
            "do not discuss", "keep this between us", "closed session", "executive meeting",
            "private inquiry", "undisclosed", "internal only"
        ],
        "credential_request": [
            "verify password", "confirm password", "enter credentials", "login", "sign in",
            "mfa", "2fa", "authenticator code", "sso certificate", "re-authenticate",
            "verify your account", "mailbox quota", "identity verification"
        ],
        "call_to_action": [
            "click here", "reply directly", "confirm once received", "confirm receipt",
            "verify now", "update immediately", "visit link", "open attached", "execute now"
        ]
    }

    @classmethod
    def analyze(cls, subject: str = "", body_text: str = "", body_html: str = "") -> Dict[str, float]:
        clean_text = TextCleaner.extract_clean_text(subject, body_text, body_html)
        if not clean_text:
            return {
                "urgency": 0.0,
                "authority": 0.0,
                "financial_pressure": 0.0,
                "fear": 0.0,
                "secrecy": 0.0,
                "credential_request": 0.0,
                "call_to_action": 0.0
            }

        scores = {}
        for dimension, keywords in cls.LEXICONS.items():
            matches = 0
            for kw in keywords:
                if kw in clean_text:
                    # Weight multi-word exact phrases higher
                    matches += (2.0 if " " in kw else 1.0)

            # Non-linear saturation curve: 1 match -> ~0.45, 2 matches -> ~0.72, 3+ matches -> ~0.88-0.95
            if matches == 0:
                score = 0.0
            elif matches == 1:
                score = 0.45
            elif matches == 2:
                score = 0.72
            elif matches == 3:
                score = 0.88
            else:
                score = min(0.88 + (matches - 3) * 0.03, 0.98)

            scores[dimension] = round(score, 2)

        return scores
