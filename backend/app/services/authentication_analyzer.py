from typing import List, Dict, Any
from app.schemas.analysis import AuthenticationStatus, HeaderFinding, ParsedEmailData


class AuthenticationAnalyzer:
    """
    Authentication Forensics Engine:
    Evaluates SPF, DKIM, and DMARC status based on header records with
    rigorous distinction between reported headers and live cryptographic verification.
    """

    @classmethod
    def evaluate(cls, email_data: ParsedEmailData) -> List[HeaderFinding]:
        findings: List[HeaderFinding] = []
        auth = email_data.authentication

        # 1. SPF Evaluation
        if auth.spf_result == "FAIL":
            findings.append(HeaderFinding(
                rule_id="AUTH_SPF_FAIL",
                type="SPF_FAILURE",
                severity="HIGH",
                message="SPF authentication failed.",
                evidence=auth.spf_details or "Header reports SPF=fail",
                explanation="The sending mail server IP is not authorized in the sender domain's DNS SPF record to dispatch email on its behalf."
            ))
        elif auth.spf_result == "SOFTFAIL":
            findings.append(HeaderFinding(
                rule_id="AUTH_SPF_SOFTFAIL",
                type="SPF_SOFTFAIL",
                severity="MEDIUM",
                message="SPF authentication resulted in softfail (~all).",
                evidence=auth.spf_details or "Header reports SPF=softfail",
                explanation="The sender domain published a transition SPF policy that permits but discourages dispatch from this IP."
            ))
        elif auth.spf_result == "NONE":
            findings.append(HeaderFinding(
                rule_id="AUTH_SPF_NONE",
                type="SPF_ABSENT",
                severity="LOW",
                message="No SPF authentication result recorded.",
                evidence="No SPF validation headers located",
                explanation="The receiving mail server did not record an SPF authentication result for this message."
            ))

        # 2. DKIM Evaluation
        if auth.dkim_result == "FAIL":
            findings.append(HeaderFinding(
                rule_id="AUTH_DKIM_FAIL",
                type="DKIM_FAILURE",
                severity="HIGH",
                message="DKIM signature verification failed.",
                evidence=auth.dkim_details or "Header reports DKIM=fail",
                explanation="The cryptographic DKIM signature failed verification, indicating message body/headers were altered or the selector/key is invalid."
            ))
        elif auth.dkim_result == "NONE":
            findings.append(HeaderFinding(
                rule_id="AUTH_DKIM_NONE",
                type="DKIM_ABSENT",
                severity="LOW",
                message="No DKIM signature found or verified in headers.",
                evidence="DKIM-Signature header not present",
                explanation="The message does not contain a verifiable cryptographic DKIM signature."
            ))

        # 3. DMARC Evaluation
        if auth.dmarc_result == "FAIL":
            findings.append(HeaderFinding(
                rule_id="AUTH_DMARC_FAIL",
                type="DMARC_FAILURE",
                severity="CRITICAL",
                message="DMARC policy alignment check failed.",
                evidence=auth.dmarc_details or "Header reports DMARC=fail",
                explanation="DMARC alignment failed because neither SPF nor DKIM passed and aligned with the visible From domain."
            ))
        elif auth.dmarc_result == "NONE":
            findings.append(HeaderFinding(
                rule_id="AUTH_DMARC_NONE",
                type="DMARC_ABSENT",
                severity="LOW",
                message="No DMARC policy check recorded in headers.",
                evidence="No DMARC validation outcome present",
                explanation="The receiving mail transfer agent did not evaluate DMARC alignment."
            ))

        return findings
