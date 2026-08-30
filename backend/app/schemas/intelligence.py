from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class IPIntelligenceData(BaseModel):
    ip: str
    is_public: bool = True
    is_private: bool = False
    is_loopback: bool = False
    is_reserved: bool = False
    country: Optional[str] = "Unknown"
    country_code: Optional[str] = "XX"
    region: Optional[str] = "Unknown"
    city: Optional[str] = "Unknown"
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = "UTC"
    isp: Optional[str] = "Unknown"
    organization: Optional[str] = "Unknown"
    asn: Optional[str] = "Unknown"
    is_hosting: bool = False
    is_proxy_vpn: bool = False
    source_context: Optional[str] = None  # e.g., "Received hop 1", "URL host"
    confidence: float = 0.8
    notes: Optional[str] = "IP geolocation represents network infrastructure, not physical person location."


class DomainIntelligenceData(BaseModel):
    domain: str
    registered_domain: Optional[str] = None
    subdomain: Optional[str] = None
    tld: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    domain_age_days: Optional[int] = None
    registrar: Optional[str] = None
    dns_a_records: List[str] = Field(default_factory=list)
    dns_mx_records: List[str] = Field(default_factory=list)
    dns_ns_records: List[str] = Field(default_factory=list)
    dns_txt_records: List[str] = Field(default_factory=list)
    is_suspicious_tld: bool = False
    lookalike_detected: bool = False
    target_brand: Optional[str] = None
    similarity_score: Optional[float] = None


class URLIntelligenceData(BaseModel):
    url: str
    scheme: str = "http"
    domain: str = ""
    registered_domain: str = ""
    path: str = ""
    query: str = ""
    has_ip_host: bool = False
    is_punycode: bool = False
    has_suspicious_keywords: bool = False
    suspicious_keywords: List[str] = Field(default_factory=list)
    entropy: float = 0.0
    risk_level: str = "LOW"
    context_text: Optional[str] = None


class IOCItem(BaseModel):
    ioc_type: str  # IP, Domain, URL, Email, SHA256, MD5
    value: str
    source: str
    risk: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    confidence: float = 1.0
    context: Optional[str] = None
