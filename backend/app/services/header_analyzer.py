from typing import List, Dict, Any, Optional
from app.schemas.analysis import HeaderFinding, ParsedEmailData


class HeaderAnalyzer:
    """
    Header Forensics Engine:
    Analyzes sender identity consistency, Reply-To mismatches, Return-Path anomalies,
    display-name spoofing indicators, and Message-ID structure.
    """

    @classmethod
    def analyze(cls, email_data: ParsedEmailData) -> List[HeaderFinding]:
        findings: List[HeaderFinding] = []

        sender = email_data.sender
        reply_to = email_data.reply_to
        return_path = email_data.return_path
        raw_headers = email_data.raw_headers

        # 1. Check Reply-To Mismatch
        if reply_to and reply_to.email:
            if sender.domain and reply_to.domain and sender.domain.lower() != reply_to.domain.lower():
                findings.append(HeaderFinding(
                    rule_id="HDR_REPLYTO_MISMATCH",
                    type="REPLY_TO_MISMATCH",
                    severity="HIGH",
                    message="Reply-To domain differs from Sender domain.",
                    evidence=f"From: {sender.email} | Reply-To: {reply_to.email}",
                    explanation="The sender specifies responses should be routed to a different external domain, a common tactic in Business Email Compromise (BEC) and phishing."
                ))
            elif sender.email.lower() != reply_to.email.lower():
                findings.append(HeaderFinding(
                    rule_id="HDR_REPLYTO_USER_DIFF",
                    type="REPLY_TO_USER_DIFF",
                    severity="MEDIUM",
                    message="Reply-To address differs from Sender address within the same domain.",
                    evidence=f"From: {sender.email} | Reply-To: {reply_to.email}",
                    explanation="Responses are redirected to an alternate mailbox under the same domain organization."
                ))

        # 2. Check Return-Path Mismatch
        if return_path and return_path.email:
            if sender.domain and return_path.domain and sender.domain.lower() != return_path.domain.lower():
                findings.append(HeaderFinding(
                    rule_id="HDR_RETURNPATH_MISMATCH",
                    type="RETURN_PATH_MISMATCH",
                    severity="MEDIUM",
                    message="Return-Path envelope domain differs from From header domain.",
                    evidence=f"From: {sender.domain} | Return-Path: {return_path.domain}",
                    explanation="Bounces and delivery notifications are directed to a third-party relay or envelope sender."
                ))

        # 3. Check Display Name Spoofing / Impersonation
        if sender.display_name:
            name_lower = sender.display_name.lower()
            # If display name contains an email address that doesn't match the actual sender email
            import re
            email_in_name = re.search(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', sender.display_name)
            if email_in_name:
                found_addr = email_in_name.group(0).lower()
                if found_addr != sender.email.lower():
                    findings.append(HeaderFinding(
                        rule_id="HDR_DISPLAY_NAME_EMAIL_SPOOF",
                        type="DISPLAY_NAME_SPOOF",
                        severity="HIGH",
                        message="Display name contains an email address differing from the actual sender mailbox.",
                        evidence=f"Display Name: '{sender.display_name}' vs Sender: {sender.email}",
                        explanation="Attackers frequently put a trusted email in the display name to mislead users on mobile and desktop clients."
                    ))

            # Executive / Authority keywords in display name
            exec_keywords = ["ceo", "chief executive", "director", "president", "managing director", "cfo", "chief financial", "admin", "it support", "security alert"]
            matched_exec = [k for k in exec_keywords if k in name_lower]
            if matched_exec:
                # If display name claims executive role but sender domain is public/external or suspicious
                findings.append(HeaderFinding(
                    rule_id="HDR_EXEC_DISPLAY_NAME",
                    type="EXECUTIVE_TITLE_CLAIM",
                    severity="LOW",
                    message=f"Display name includes executive/authority title ('{matched_exec[0].upper()}').",
                    evidence=f"Display Name: '{sender.display_name}'",
                    explanation="Executive and authority titles are commonly leveraged in social engineering and authority-bias pretexting."
                ))

        # 4. Check Message-ID Consistency
        if email_data.message_id and sender.domain:
            msg_id = email_data.message_id.lower()
            if "@" in msg_id:
                msg_id_domain = msg_id.split("@")[-1].strip(">").strip()
                if msg_id_domain and not sender.domain.endswith(msg_id_domain) and not msg_id_domain.endswith(sender.domain):
                    findings.append(HeaderFinding(
                        rule_id="HDR_MSGID_DOMAIN_ANOMALY",
                        type="MESSAGE_ID_ANOMALY",
                        severity="LOW",
                        message="Message-ID domain does not match sender domain.",
                        evidence=f"Message-ID: {email_data.message_id} | Sender: {sender.domain}",
                        explanation="The Message-ID was generated by a host infrastructure with a different domain than the sender."
                    ))

        # 5. Check for Suspicious X-Mailer or Mail Client headers
        for h_key, h_val in raw_headers.items():
            if h_key.lower() in {"x-mailer", "user-agent", "x-mime-autoconverted"}:
                val_str = str(h_val).lower()
                if any(tool in val_str for tool in ["phpmailer", "massmail", "bulletproof", "python", "curl", "wget"]):
                    findings.append(HeaderFinding(
                        rule_id="HDR_SUSPICIOUS_MAILER",
                        type="SUSPICIOUS_CLIENT",
                        severity="HIGH",
                        message=f"Suspicious or automated mail client detected in {h_key}.",
                        evidence=f"{h_key}: {h_val}",
                        explanation="Automated bulk mailing scripts or command-line utilities were used to generate this message."
                    ))

        return findings
