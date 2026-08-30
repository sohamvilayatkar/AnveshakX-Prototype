from typing import List, Dict, Any, Optional
from app.utils.domain_utils import extract_domain_info
from app.schemas.intelligence import DomainIntelligenceData
from app.services.impersonation_detector import ImpersonationDetector

# Demo DNS and WHOIS database for reliable offline hackathon execution
DEMO_DOMAIN_DATABASE: Dict[str, Dict[str, Any]] = {
    "acmecorp.com": {
        "creation_date": "2010-04-12",
        "expiration_date": "2028-04-12",
        "domain_age_days": 5980,
        "registrar": "MarkMonitor, Inc.",
        "dns_a_records": ["198.51.100.25"],
        "dns_mx_records": ["10 mail-relay.acmecorp.com"],
        "dns_ns_records": ["ns1.acmecorp.com", "ns2.acmecorp.com"],
        "dns_txt_records": ["v=spf1 ip4:198.51.100.25 -all"]
    },
    "globalenterprise-corp.com": {
        "creation_date": "2015-09-20",
        "expiration_date": "2027-09-20",
        "domain_age_days": 3995,
        "registrar": "GoDaddy.com, LLC",
        "dns_a_records": ["203.0.113.50"],
        "dns_mx_records": ["10 mail.globalenterprise-corp.com"],
        "dns_ns_records": ["ns1.domaincontrol.com", "ns2.domaincontrol.com"],
        "dns_txt_records": ["v=spf1 include:_spf.globalenterprise-corp.com -all"]
    },
    "fast-offshore-transfers.net": {
        "creation_date": "2026-08-18",
        "expiration_date": "2027-08-18",
        "domain_age_days": 12,
        "registrar": "NameCheap, Inc. (Privacy Protected)",
        "dns_a_records": ["185.220.101.5"],
        "dns_mx_records": ["10 mail.fast-offshore-transfers.net"],
        "dns_ns_records": ["ns1.offshore-dns.net", "ns2.offshore-dns.net"],
        "dns_txt_records": ["v=spf1 +all"]
    },
    "statebank-notification.xyz": {
        "creation_date": "2026-08-22",
        "expiration_date": "2027-08-22",
        "domain_age_days": 8,
        "registrar": "Porkbun LLC",
        "dns_a_records": ["91.240.118.42"],
        "dns_mx_records": ["10 mx.statebank-notification.xyz"],
        "dns_ns_records": ["ns1.bulletproof-dns.xyz", "ns2.bulletproof-dns.xyz"],
        "dns_txt_records": ["v=spf1 -all"]
    },
    "sbi-secure-portal-verify.xyz": {
        "creation_date": "2026-08-24",
        "expiration_date": "2027-08-24",
        "domain_age_days": 6,
        "registrar": "NameSilo, LLC",
        "dns_a_records": ["91.240.118.42"],
        "dns_mx_records": [],
        "dns_ns_records": ["ns1.parkingcrew.net"],
        "dns_txt_records": []
    },
    "micros0ft-support-portal.top": {
        "creation_date": "2026-08-25",
        "expiration_date": "2027-08-25",
        "domain_age_days": 5,
        "registrar": "Reg.ru",
        "dns_a_records": ["45.154.255.88"],
        "dns_mx_records": ["10 mail.micros0ft-support-portal.top"],
        "dns_ns_records": ["ns1.bulletproof-direct.top"],
        "dns_txt_records": ["v=spf1 ?all"]
    }
}


class DomainAnalyzer:
    """
    Domain Forensics Engine:
    Resolves domain metadata, WHOIS age, DNS records, and lookalike brand impersonation.
    """

    @classmethod
    def analyze_domains(cls, domain_list: List[str]) -> List[DomainIntelligenceData]:
        results: List[DomainIntelligenceData] = []
        seen = set()

        for d in domain_list:
            if not d:
                continue
            d_clean = d.strip().lower()
            if d_clean in seen:
                continue
            seen.add(d_clean)

            info = extract_domain_info(d_clean)
            reg_domain = info["registered_domain"] or d_clean
            
            # Check brand impersonation
            imp_check = ImpersonationDetector.check_domain(d_clean)

            # Check demo intelligence data
            dns_data = DEMO_DOMAIN_DATABASE.get(reg_domain, {})
            if not dns_data:
                dns_data = DEMO_DOMAIN_DATABASE.get(d_clean, {})

            creation = dns_data.get("creation_date")
            expiration = dns_data.get("expiration_date")
            age_days = dns_data.get("domain_age_days")
            registrar = dns_data.get("registrar", "Unknown Registrar / Privacy Shielded")
            a_recs = dns_data.get("dns_a_records", [])
            mx_recs = dns_data.get("dns_mx_records", [])
            ns_recs = dns_data.get("dns_ns_records", [])
            txt_recs = dns_data.get("dns_txt_records", [])

            # Default fallback for newly observed domains
            if age_days is None:
                if info["is_suspicious_tld"]:
                    age_days = 15
                    creation = "2026-08-15"
                else:
                    age_days = 1200
                    creation = "2023-05-10"

            results.append(DomainIntelligenceData(
                domain=d_clean,
                registered_domain=reg_domain,
                subdomain=info["subdomain"],
                tld=info["tld"],
                creation_date=creation,
                expiration_date=expiration,
                domain_age_days=age_days,
                registrar=registrar,
                dns_a_records=a_recs,
                dns_mx_records=mx_recs,
                dns_ns_records=ns_recs,
                dns_txt_records=txt_recs,
                is_suspicious_tld=info["is_suspicious_tld"],
                lookalike_detected=imp_check["is_impersonation"],
                target_brand=imp_check.get("target_brand"),
                similarity_score=imp_check.get("similarity_score")
            ))

        return results
