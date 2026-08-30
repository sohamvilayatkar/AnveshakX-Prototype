from pathlib import Path
from app.services.email_parser import EmailParser


def test_parse_legitimate_email():
    eml_path = Path(__file__).resolve().parent.parent.parent / "sample_emails" / "legitimate.eml"
    with open(eml_path, "rb") as f:
        raw_bytes = f.read()

    result = EmailParser.parse(raw_bytes)
    assert result.subject == "Project AnveshakX Sprint Planning Review"
    assert result.sender.email == "alice@acmecorp.com"
    assert result.sender.display_name == "Alice Roberts"
    assert result.sender.domain == "acmecorp.com"
    assert len(result.recipients_to) == 1
    assert result.recipients_to[0].email == "employee@enterprise-receiver.net"
    assert result.authentication.spf_result == "PASS"
    assert result.authentication.dkim_result == "PASS"
    assert result.authentication.dmarc_result == "PASS"
    assert len(result.received_hops) == 2
    assert result.earliest_source_ip == "198.51.100.25"
    assert len(result.urls) >= 1
    assert any("portal.acmecorp.com" in u.domain for u in result.urls)


def test_parse_bec_email():
    eml_path = Path(__file__).resolve().parent.parent.parent / "sample_emails" / "bec.eml"
    with open(eml_path, "rb") as f:
        raw_bytes = f.read()

    result = EmailParser.parse(raw_bytes)
    assert "URGENT & CONFIDENTIAL" in result.subject
    assert result.sender.email == "ceo@globalenterprise-corp.com"
    assert result.sender.domain == "globalenterprise-corp.com"
    assert result.reply_to is not None
    assert result.reply_to.email == "executive-desk-urgent@fast-offshore-transfers.net"
    assert result.reply_to.domain == "fast-offshore-transfers.net"
    assert result.return_path is not None
    assert result.return_path.email == "bounce-daemon@unregistered-relay-node.com"
    assert result.authentication.spf_result == "FAIL"
    assert result.authentication.dmarc_result == "FAIL"
    assert result.earliest_source_ip == "185.220.101.5"
    assert len(result.received_hops) == 2


def test_parse_phishing_email():
    eml_path = Path(__file__).resolve().parent.parent.parent / "sample_emails" / "phishing.eml"
    with open(eml_path, "rb") as f:
        raw_bytes = f.read()

    result = EmailParser.parse(raw_bytes)
    assert "Suspended" in result.subject
    assert result.sender.domain == "statebank-notification.xyz"
    assert len(result.urls) >= 1
    # Check that the anchor URL was extracted
    phish_url = next((u for u in result.urls if "sbi-secure-portal-verify.xyz" in u.domain), None)
    assert phish_url is not None
    assert phish_url.has_suspicious_keywords is True
    assert phish_url.context_text == "Verify Account Now"


def test_parse_impersonation_with_attachment():
    eml_path = Path(__file__).resolve().parent.parent.parent / "sample_emails" / "impersonation.eml"
    with open(eml_path, "rb") as f:
        raw_bytes = f.read()

    result = EmailParser.parse(raw_bytes)
    assert len(result.attachments) == 1
    att = result.attachments[0]
    assert att.filename == "invoice_overdue_scan.pdf.exe"
    assert att.is_suspicious is True
    assert len(att.sha256_hash) == 64
    assert len(att.md5_hash) == 32
    assert any("double extension" in r.lower() for r in att.suspicion_reasons)


def test_parse_malformed_email_never_crashes():
    # Corrupted / partial byte stream without headers
    malformed_bytes = b"Subject: Broken\r\n\r\nThis is just a broken email body with invalid formatting."
    result = EmailParser.parse(malformed_bytes)
    assert result.subject == "Broken"
    assert result.sender.email == ""
    assert result.authentication.spf_result == "NONE"

    # Empty bytes
    empty_result = EmailParser.parse(b"")
    assert empty_result.subject == ""
    assert empty_result.sender.email == ""
