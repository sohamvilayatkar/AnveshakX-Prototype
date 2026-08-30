from typing import List, Set
from app.schemas.analysis import ParsedEmailData
from app.schemas.intelligence import IOCItem, IPIntelligenceData, DomainIntelligenceData, URLIntelligenceData


class IndicatorExtractor:
    """
    Forensic IOC Extractor:
    Aggregates and formats all Indicators of Compromise (IPs, Domains, URLs, Hashes, Emails)
    with risk ratings and origin context into a standardized investigation table.
    """

    @classmethod
    def extract_all(
        cls,
        email_data: ParsedEmailData,
        ip_intel: List[IPIntelligenceData],
        domain_intel: List[DomainIntelligenceData]
    ) -> List[IOCItem]:
        iocs: List[IOCItem] = []
        seen: Set[str] = set()

        def add_ioc(ioc_type: str, value: str, source: str, risk: str, confidence: float, context: str = ""):
            key = f"{ioc_type}:{value.lower()}"
            if key not in seen and value.strip():
                seen.add(key)
                iocs.append(IOCItem(
                    ioc_type=ioc_type,
                    value=value.strip(),
                    source=source,
                    risk=risk,
                    confidence=confidence,
                    context=context or None
                ))

        # 1. Sender & Identity Emails
        if email_data.sender.email:
            add_ioc("Email", email_data.sender.email, "From Header", "INFO", 1.0, f"Display Name: '{email_data.sender.display_name}'")
        if email_data.reply_to and email_data.reply_to.email:
            risk = "HIGH" if (email_data.sender.domain and email_data.reply_to.domain != email_data.sender.domain) else "LOW"
            add_ioc("Email", email_data.reply_to.email, "Reply-To Header", risk, 0.95, "Response redirect destination")
        if email_data.return_path and email_data.return_path.email:
            add_ioc("Email", email_data.return_path.email, "Return-Path Header", "INFO", 0.9, "Envelope bounce address")

        # 2. IP Addresses & Geolocation Context
        for ip_data in ip_intel:
            risk = "HIGH" if (ip_data.is_hosting and ip_data.is_proxy_vpn) else ("MEDIUM" if ip_data.is_hosting else "LOW")
            if not ip_data.is_public:
                risk = "INFO"
            ctx = f"Org: {ip_data.organization} | Location: {ip_data.city}, {ip_data.country} ({ip_data.asn})"
            add_ioc("IP", ip_data.ip, ip_data.source_context or "Received Relay", risk, ip_data.confidence, ctx)

        # 3. Domains & Lookalike Context
        for dom_data in domain_intel:
            risk = "CRITICAL" if dom_data.lookalike_detected else ("HIGH" if dom_data.is_suspicious_tld else "LOW")
            ctx = f"Age: {dom_data.domain_age_days}d | Registrar: {dom_data.registrar}"
            if dom_data.lookalike_detected:
                ctx += f" | Lookalike target: {dom_data.target_brand}"
            add_ioc("Domain", dom_data.domain, "Extracted Infrastructure", risk, 0.9, ctx)

        # 4. URLs
        for u in email_data.urls:
            add_ioc("URL", u.url, "Email Body Link", u.risk_level, 0.92, f"Anchor Text: '{u.context_text or ''}'")

        # 5. Attachment Hashes
        for att in email_data.attachments:
            risk = "HIGH" if att.is_suspicious else "LOW"
            add_ioc("SHA256", att.sha256_hash, f"Attachment: {att.filename}", risk, 1.0, f"Size: {att.size_bytes} bytes | MIME: {att.content_type}")
            add_ioc("MD5", att.md5_hash, f"Attachment: {att.filename}", risk, 1.0, f"Filename: {att.filename}")

        return iocs
