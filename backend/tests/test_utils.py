import pytest
from app.utils.hashing import compute_sha256, compute_md5, compute_hashes
from app.utils.ip_utils import extract_ips_from_text, classify_ip
from app.utils.domain_utils import extract_domain_info, calculate_entropy, parse_url_intelligence
from app.utils.validators import validate_email_file


def test_compute_hashes():
    test_data = b"AnveshakX Forensic Evidence Sample 2026"
    sha256_hash, md5_hash = compute_hashes(test_data)
    assert len(sha256_hash) == 64
    assert len(md5_hash) == 32
    assert sha256_hash == compute_sha256(test_data)
    assert md5_hash == compute_md5(test_data)


def test_ip_extraction_and_classification():
    sample_text = """
    Received from 192.168.1.50 (private)
    Relayed through 185.220.101.5 (public)
    Loopback test 127.0.0.1
    IPv6 sample 2001:0db8:85a3:0000:0000:8a2e:0370:7334
    Invalid 999.888.777.666
    """
    ips = extract_ips_from_text(sample_text)
    assert "192.168.1.50" in ips
    assert "185.220.101.5" in ips
    assert "127.0.0.1" in ips
    assert "2001:db8:85a3::8a2e:370:7334" in ips or "2001:0db8:85a3:0000:0000:8a2e:0370:7334" in ips

    # Classification tests
    priv_info = classify_ip("192.168.1.50")
    assert priv_info["is_private"] is True
    assert priv_info["is_public"] is False

    pub_info = classify_ip("185.220.101.5")
    assert pub_info["is_public"] is True
    assert pub_info["is_private"] is False

    loop_info = classify_ip("127.0.0.1")
    assert loop_info["is_loopback"] is True


def test_domain_info_extraction():
    info = extract_domain_info("https://sub.portal.sbi.co.in/login")
    assert info["registered_domain"] == "sbi.co.in"
    assert info["tld"] == "co.in"
    assert "sub.portal" in info["subdomain"]
    assert info["is_suspicious_tld"] is False

    suspicious_info = extract_domain_info("http://phish-secure-login.xyz")
    assert suspicious_info["registered_domain"] == "phish-secure-login.xyz"
    assert suspicious_info["tld"] == "xyz"
    assert suspicious_info["is_suspicious_tld"] is True


def test_url_intelligence_parsing():
    url = "https://sbi-secure-portal-verify.xyz/login/auth-session?ref=99281"
    parsed = parse_url_intelligence(url, context_text="Click here to verify")
    assert parsed["domain"] == "sbi-secure-portal-verify.xyz"
    assert parsed["registered_domain"] == "sbi-secure-portal-verify.xyz"
    assert parsed["has_suspicious_keywords"] is True
    assert "login" in parsed["suspicious_keywords"]
    assert "verify" in parsed["suspicious_keywords"]
    assert parsed["risk_level"] in {"MEDIUM", "HIGH"}
    assert parsed["context_text"] == "Click here to verify"


def test_validate_email_file():
    valid, msg = validate_email_file("sample.eml", "message/rfc822", 1024)
    assert valid is True

    valid_txt, _ = validate_email_file("sample.txt", "text/plain", 1024)
    assert valid_txt is True

    invalid_ext, err_ext = validate_email_file("malicious.exe", "application/x-msdownload", 1024)
    assert invalid_ext is False
    assert "Invalid file extension" in err_ext

    invalid_empty, err_empty = validate_email_file("empty.eml", "message/rfc822", 0)
    assert invalid_empty is False
    assert "empty" in err_empty
