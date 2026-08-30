import re
import math
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import tldextract

# URL extraction regex supporting http, https, ftp
URL_REGEX = re.compile(
    r'(?:https?|ftp)://[^\s/$.?#].[^\s]*',
    re.IGNORECASE
)

# Email address extraction regex
EMAIL_REGEX = re.compile(
    r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
)

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "banking", "signin",
    "password", "auth", "confirm", "wallet", "support", "invoice", "payment",
    "transfer", "wire", "urgent", "beneficiary", "suspended", "security"
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "buzz", "gq", "cf", "ml", "tk", "ga",
    "country", "stream", "download", "racing", "win", "bid", "loan", "men",
    "icu", "monster", "rest", "fit"
}


def extract_domain_info(domain_or_url: str) -> Dict[str, Any]:
    """
    Extract structured domain information (subdomain, registered domain, TLD).
    Uses tldextract to accurately handle multi-level TLDs like co.in, com.br, etc.
    """
    if not domain_or_url:
        return {
            "domain": "",
            "registered_domain": "",
            "subdomain": "",
            "tld": "",
            "is_suspicious_tld": False
        }

    # If it's a URL, extract host
    if "://" in domain_or_url:
        parsed = urlparse(domain_or_url)
        domain_or_url = parsed.hostname or domain_or_url

    ext = tldextract.extract(domain_or_url)
    registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    full_domain = f"{ext.subdomain}.{registered_domain}" if ext.subdomain else registered_domain
    
    tld = ext.suffix.lower()
    is_suspicious_tld = tld in SUSPICIOUS_TLDS or any(tld.endswith("." + s) for s in SUSPICIOUS_TLDS)

    return {
        "domain": full_domain.lower(),
        "registered_domain": registered_domain.lower(),
        "subdomain": ext.subdomain.lower(),
        "tld": tld,
        "is_suspicious_tld": is_suspicious_tld
    }


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string to detect randomized/DGA domain names."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def parse_url_intelligence(url_str: str, context_text: Optional[str] = None) -> Dict[str, Any]:
    """Parse URL into forensic components and evaluate risk attributes."""
    try:
        parsed = urlparse(url_str)
        hostname = parsed.hostname or ""
        scheme = parsed.scheme or "http"
        path = parsed.path or ""
        query = parsed.query or ""
        
        domain_info = extract_domain_info(hostname)
        
        # Check if hostname is an IP address
        has_ip_host = False
        import ipaddress
        try:
            ipaddress.ip_address(hostname)
            has_ip_host = True
        except ValueError:
            pass

        is_punycode = "xn--" in hostname.lower()
        
        # Find suspicious keywords in url and path
        matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_str.lower()]
        
        # Calculate risk score heuristic
        risk = "LOW"
        if has_ip_host or is_punycode or len(matched_keywords) >= 3 or domain_info["is_suspicious_tld"]:
            risk = "HIGH"
        elif len(matched_keywords) >= 1 or len(url_str) > 120 or domain_info["subdomain"].count('.') >= 2:
            risk = "MEDIUM"

        return {
            "url": url_str,
            "scheme": scheme,
            "domain": domain_info["domain"],
            "registered_domain": domain_info["registered_domain"],
            "path": path,
            "query": query,
            "has_ip_host": has_ip_host,
            "is_punycode": is_punycode,
            "has_suspicious_keywords": len(matched_keywords) > 0,
            "suspicious_keywords": matched_keywords,
            "entropy": calculate_entropy(hostname),
            "risk_level": risk,
            "context_text": context_text
        }
    except Exception:
        return {
            "url": url_str,
            "scheme": "http",
            "domain": url_str,
            "registered_domain": url_str,
            "path": "",
            "query": "",
            "has_ip_host": False,
            "is_punycode": False,
            "has_suspicious_keywords": False,
            "suspicious_keywords": [],
            "entropy": 0.0,
            "risk_level": "LOW",
            "context_text": context_text
        }
