import re
import ipaddress
from typing import List, Dict, Any, Optional

# Strict IPv4 regex: matching 4 octets each 0-255
IPV4_REGEX = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

# Standard IPv6 regex
IPV6_REGEX = re.compile(
    r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,7}:|'
    r':(?::[0-9a-fA-F]{1,4}){1,7}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}'
)


def extract_ips_from_text(text: str) -> List[str]:
    """Extract all valid IPv4 and IPv6 addresses from an unstructured text string."""
    if not text:
        return []
    
    ips = set()
    for match in IPV4_REGEX.finditer(text):
        ip_str = match.group(0)
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            ips.add(str(ip_obj))
        except ValueError:
            continue

    for match in IPV6_REGEX.finditer(text):
        ip_str = match.group(0)
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            ips.add(str(ip_obj))
        except ValueError:
            continue

    return list(ips)


RFC_1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),   # Loopback v4
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local v4
    ipaddress.ip_network("fc00::/7"),      # Unique Local Address (ULA) v6
    ipaddress.ip_network("fe80::/10"),     # Link-local v6
    ipaddress.ip_network("::1/128"),       # Loopback v6
]


def classify_ip(ip_str: str) -> Dict[str, Any]:
    """
    Classify an IP as public, private, loopback, or reserved.
    Provides forensic safety: only public IPs are queried externally.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        is_loopback = ip.is_loopback
        is_link_local = ip.is_link_local
        is_multicast = ip.is_multicast
        is_unspecified = ip.is_unspecified
        is_private = any(ip in net for net in RFC_1918_NETWORKS[:4]) or (ip.version == 6 and ip in RFC_1918_NETWORKS[6])
        is_reserved = ip.is_reserved

        # An IP is considered public/external if it is not in private/internal subnets or loopback/link-local/multicast
        is_public = not (is_private or is_loopback or is_link_local or is_multicast or is_unspecified)

        return {
            "ip": str(ip),
            "version": ip.version,
            "is_public": is_public,
            "is_private": is_private,
            "is_loopback": is_loopback,
            "is_reserved": is_reserved
        }
    except ValueError:
        return {
            "ip": ip_str,
            "version": 0,
            "is_public": False,
            "is_private": False,
            "is_loopback": False,
            "is_reserved": False,
            "invalid": True
        }
