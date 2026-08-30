import abc
from typing import Dict, Any, List, Optional
import httpx
from app.config import settings
from app.schemas.intelligence import IPIntelligenceData
from app.utils.ip_utils import classify_ip

# Deterministic demo database for reliable, offline SIH presentation
DEMO_IP_DATABASE: Dict[str, Dict[str, Any]] = {
    "185.220.101.5": {
        "country": "Germany",
        "country_code": "DE",
        "region": "Hesse",
        "city": "Frankfurt",
        "latitude": 50.1109,
        "longitude": 8.6821,
        "timezone": "Europe/Berlin",
        "isp": "Zwiebelfreunde e.V.",
        "organization": "Tor Exit Node Network",
        "asn": "AS200651",
        "is_hosting": True,
        "is_proxy_vpn": True,
        "notes": "Known bulletproof host / privacy routing proxy."
    },
    "91.240.118.42": {
        "country": "Seychelles",
        "country_code": "SC",
        "region": "Victoria",
        "city": "Victoria",
        "latitude": -4.6191,
        "longitude": 55.4513,
        "timezone": "Indian/Mahe",
        "isp": "Offshore Cloud Infrastructure Ltd",
        "organization": "Darknet Bulletproof Host",
        "asn": "AS49870",
        "is_hosting": True,
        "is_proxy_vpn": True,
        "notes": "Offshore bulletproof hosting cluster associated with phishing campaigns."
    },
    "45.154.255.88": {
        "country": "Netherlands",
        "country_code": "NL",
        "region": "North Holland",
        "city": "Amsterdam",
        "latitude": 52.3676,
        "longitude": 4.9041,
        "timezone": "Europe/Amsterdam",
        "isp": "Serverius Holding B.V.",
        "organization": "Direct VPS Infrastructure",
        "asn": "AS50673",
        "is_hosting": True,
        "is_proxy_vpn": False,
        "notes": "High-risk VPS infrastructure used in credential phishing relays."
    },
    "194.26.29.112": {
        "country": "Romania",
        "country_code": "RO",
        "region": "Bucharest",
        "city": "Bucharest",
        "latitude": 44.4268,
        "longitude": 26.1025,
        "timezone": "Europe/Bucharest",
        "isp": "M247 Ltd",
        "organization": "M247 Infrastructure",
        "asn": "AS9009",
        "is_hosting": True,
        "is_proxy_vpn": True,
        "notes": "Proxy/VPN relay infrastructure observed in authentication attempts."
    },
    "198.51.100.25": {
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "San Jose",
        "latitude": 37.3382,
        "longitude": -121.8863,
        "timezone": "America/Los_Angeles",
        "isp": "Acme Corp Enterprise Network",
        "organization": "Corporate Mail Gateway",
        "asn": "AS15169",
        "is_hosting": False,
        "is_proxy_vpn": False,
        "notes": "Authorized corporate enterprise mail relay."
    },
    "203.0.113.10": {
        "country": "India",
        "country_code": "IN",
        "region": "Maharashtra",
        "city": "Mumbai",
        "latitude": 19.0760,
        "longitude": 72.8777,
        "timezone": "Asia/Kolkata",
        "isp": "Target Enterprise MX Relay",
        "organization": "Corporate Inbound MX",
        "asn": "AS45609",
        "is_hosting": False,
        "is_proxy_vpn": False,
        "notes": "Recipient enterprise edge mail gateway."
    },
    "198.51.100.99": {
        "country": "United States",
        "country_code": "US",
        "region": "Virginia",
        "city": "Ashburn",
        "latitude": 39.0438,
        "longitude": -77.4874,
        "timezone": "America/New_York",
        "isp": "ISP Inbound Gateway",
        "organization": "Public Inbound Transit",
        "asn": "AS7018",
        "is_hosting": True,
        "is_proxy_vpn": False,
        "notes": "ISP transit gateway."
    },
    "198.51.100.110": {
        "country": "United States",
        "country_code": "US",
        "region": "Oregon",
        "city": "Portland",
        "latitude": 45.5152,
        "longitude": -122.6784,
        "timezone": "America/Los_Angeles",
        "isp": "Edge Defense Security Gateway",
        "organization": "Secure Email Gateway",
        "asn": "AS16509",
        "is_hosting": True,
        "is_proxy_vpn": False,
        "notes": "Edge email security appliance."
    }
}


class BaseIPIntelligenceProvider(abc.ABC):
    @abc.abstractmethod
    def lookup(self, ip_str: str, context: Optional[str] = None) -> IPIntelligenceData:
        pass


class MockIPIntelligenceProvider(BaseIPIntelligenceProvider):
    """Deterministic intelligence provider for offline testing and hackathon demonstration."""

    def lookup(self, ip_str: str, context: Optional[str] = None) -> IPIntelligenceData:
        classification = classify_ip(ip_str)
        is_pub = classification.get("is_public", False)
        is_priv = classification.get("is_private", False)
        is_loop = classification.get("is_loopback", False)

        if not is_pub:
            return IPIntelligenceData(
                ip=ip_str,
                is_public=False,
                is_private=is_priv,
                is_loopback=is_loop,
                country="Internal / Private",
                country_code="LOCAL",
                region="Local Network",
                city="Local Subnet",
                isp="Internal Intranet / RFC 1918",
                organization="Private Network Segment",
                asn="N/A (Private)",
                is_hosting=False,
                is_proxy_vpn=False,
                source_context=context,
                confidence=1.0,
                notes="Private network address space not routable on the public Internet."
            )

        # Check demo dataset
        if ip_str in DEMO_IP_DATABASE:
            demo_info = DEMO_IP_DATABASE[ip_str]
            return IPIntelligenceData(
                ip=ip_str,
                is_public=True,
                is_private=False,
                country=demo_info["country"],
                country_code=demo_info["country_code"],
                region=demo_info["region"],
                city=demo_info["city"],
                latitude=demo_info["latitude"],
                longitude=demo_info["longitude"],
                timezone=demo_info["timezone"],
                isp=demo_info["isp"],
                organization=demo_info["organization"],
                asn=demo_info["asn"],
                is_hosting=demo_info["is_hosting"],
                is_proxy_vpn=demo_info["is_proxy_vpn"],
                source_context=context,
                confidence=0.92,
                notes=demo_info["notes"]
            )

        # Default synthetic public IP fallback
        # Hash IP into deterministic coordinates
        import hashlib
        h = int(hashlib.md5(ip_str.encode()).hexdigest()[:8], 16)
        lat = round(20.0 + (h % 300) / 10.0, 4)
        lon = round(-40.0 + ((h // 300) % 600) / 10.0, 4)

        return IPIntelligenceData(
            ip=ip_str,
            is_public=True,
            country="External Infrastructure",
            country_code="UN",
            region="External Region",
            city="Associated Node",
            latitude=lat,
            longitude=lon,
            isp=f"Transit Carrier ASN-{h % 65000}",
            organization=f"Network Host {ip_str}",
            asn=f"AS{h % 65000}",
            is_hosting=True,
            is_proxy_vpn=False,
            source_context=context,
            confidence=0.75,
            notes="Probable source infrastructure. IP geolocation is approximate."
        )


class LiveIPIntelligenceProvider(BaseIPIntelligenceProvider):
    """Live IP Geolocation provider using ip-api.com with local mock fallback."""

    def __init__(self, fallback_provider: BaseIPIntelligenceProvider):
        self.fallback = fallback_provider

    def lookup(self, ip_str: str, context: Optional[str] = None) -> IPIntelligenceData:
        classification = classify_ip(ip_str)
        if not classification.get("is_public", False):
            return self.fallback.lookup(ip_str, context)

        # First check demo database for guaranteed high-fidelity demonstration
        if ip_str in DEMO_IP_DATABASE:
            return self.fallback.lookup(ip_str, context)

        try:
            url = f"http://ip-api.com/json/{ip_str}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,hosting,proxy"
            with httpx.Client(timeout=2.0) as client:
                res = client.get(url)
                if res.status_code == 200:
                    data = res.json()
                    if data.get("status") == "success":
                        return IPIntelligenceData(
                            ip=ip_str,
                            is_public=True,
                            country=data.get("country", "Unknown"),
                            country_code=data.get("countryCode", "XX"),
                            region=data.get("regionName", "Unknown"),
                            city=data.get("city", "Unknown"),
                            latitude=data.get("lat"),
                            longitude=data.get("lon"),
                            timezone=data.get("timezone", "UTC"),
                            isp=data.get("isp", "Unknown ISP"),
                            organization=data.get("org", "Unknown Org"),
                            asn=data.get("as", "Unknown ASN"),
                            is_hosting=bool(data.get("hosting", False)),
                            is_proxy_vpn=bool(data.get("proxy", False)),
                            source_context=context,
                            confidence=0.88,
                            notes="Live queried geolocation data (approximate network location)."
                        )
        except Exception:
            pass

        return self.fallback.lookup(ip_str, context)


class IPIntelligenceService:
    """Service facade for IP Intelligence resolution."""
    _mock_provider = MockIPIntelligenceProvider()
    _live_provider = LiveIPIntelligenceProvider(_mock_provider)

    @classmethod
    def get_provider(cls) -> BaseIPIntelligenceProvider:
        if settings.IP_INTELLIGENCE_ENABLED:
            return cls._live_provider
        return cls._mock_provider

    @classmethod
    def analyze_ips(cls, ip_list: List[str], earliest_source_ip: Optional[str] = None) -> List[IPIntelligenceData]:
        provider = cls.get_provider()
        results: List[IPIntelligenceData] = []
        seen = set()

        # Prioritize earliest source IP first if provided
        ordered_ips = []
        if earliest_source_ip and earliest_source_ip not in seen:
            ordered_ips.append((earliest_source_ip, "Probable earliest visible source IP"))
            seen.add(earliest_source_ip)

        for ip in ip_list:
            if ip not in seen:
                ordered_ips.append((ip, "Observed in headers / content"))
                seen.add(ip)

        for ip, ctx in ordered_ips:
            data = provider.lookup(ip, context=ctx)
            results.append(data)

        return results
