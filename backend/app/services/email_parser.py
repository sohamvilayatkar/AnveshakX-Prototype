import email
from email import policy
from email.utils import parseaddr, getaddresses
import re
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from bs4 import BeautifulSoup
import dateutil.parser

from app.utils.hashing import compute_hashes
from app.utils.ip_utils import extract_ips_from_text, classify_ip, IPV4_REGEX
from app.utils.domain_utils import extract_domain_info, parse_url_intelligence, URL_REGEX
from app.schemas.analysis import (
    EmailAddressInfo, AttachmentInfo, ReceivedHop, AuthenticationStatus,
    ParsedEmailData
)

SUSPICIOUS_ATTACHMENT_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".cpl",
    ".wsf", ".jar", ".iso", ".img", ".lnk", ".pif", ".reg", ".docm", ".xlsm",
    ".pptm", ".vbe", ".jse", ".wsh"
}


class EmailParser:
    """
    Forensic Email Parser:
    Extracts structured forensic data, authentication signals, relay paths,
    IOCs, URLs, attachments, and headers without crashing on malformed inputs.
    """

    @classmethod
    def parse(cls, raw_bytes: bytes) -> ParsedEmailData:
        """Parse raw email bytes into a structured ParsedEmailData object."""
        try:
            msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        except Exception:
            # Fallback to compat32 policy if default policy fails on corrupted email
            msg = email.message_from_bytes(raw_bytes, policy=policy.compat32)

        # 1. Headers Extraction
        raw_headers = {}
        for header, val in msg.items():
            if header in raw_headers:
                if isinstance(raw_headers[header], list):
                    raw_headers[header].append(str(val))
                else:
                    raw_headers[header] = [raw_headers[header], str(val)]
            else:
                raw_headers[header] = str(val)

        message_id = str(msg.get("Message-ID", "")).strip() or None
        subject = str(msg.get("Subject", "")).strip()
        date_header = str(msg.get("Date", "")).strip() or None

        # 2. Sender and Identity
        sender = cls._parse_single_address(msg.get("From", ""))
        reply_to = cls._parse_single_address(msg.get("Reply-To", "")) if msg.get("Reply-To") else None
        return_path = cls._parse_single_address(msg.get("Return-Path", "")) if msg.get("Return-Path") else None

        recipients_to = cls._parse_address_list(msg.get_all("To", []))
        recipients_cc = cls._parse_address_list(msg.get_all("Cc", []))
        recipients_bcc = cls._parse_address_list(msg.get_all("Bcc", []))

        # 3. Received Headers / Relay Analysis
        received_raw_list = msg.get_all("Received", [])
        received_hops = cls._parse_received_headers(received_raw_list)
        earliest_source_ip = cls._determine_earliest_source_ip(received_hops)

        # 4. Authentication Headers
        auth_status = cls._parse_authentication_headers(msg, raw_headers)

        # 5. Extract Body & Attachments
        body_text, body_html, attachments = cls._extract_content_and_attachments(msg)

        # 6. Extract URLs
        urls = cls._extract_urls(body_text, body_html)

        # 7. Extract IPs and Domains
        all_text_for_iocs = f"{body_text} {body_html} {' '.join(str(v) for v in received_raw_list)}"
        extracted_ips = list(set(extract_ips_from_text(all_text_for_iocs)))
        
        extracted_domains = set()
        if sender.domain:
            extracted_domains.add(sender.domain)
        if reply_to and reply_to.domain:
            extracted_domains.add(reply_to.domain)
        if return_path and return_path.domain:
            extracted_domains.add(return_path.domain)
        for u in urls:
            if u.domain:
                extracted_domains.add(u.domain)
            if u.registered_domain:
                extracted_domains.add(u.registered_domain)

        return ParsedEmailData(
            message_id=message_id,
            subject=subject,
            date_header=date_header,
            sender=sender,
            reply_to=reply_to,
            return_path=return_path,
            recipients_to=recipients_to,
            recipients_cc=recipients_cc,
            recipients_bcc=recipients_bcc,
            received_hops=received_hops,
            earliest_source_ip=earliest_source_ip,
            authentication=auth_status,
            urls=urls,
            extracted_ips=extracted_ips,
            extracted_domains=list(extracted_domains),
            attachments=attachments,
            body_text=body_text,
            body_html=body_html,
            raw_headers=raw_headers
        )

    @classmethod
    def _parse_single_address(cls, header_value: str) -> EmailAddressInfo:
        """Extract display name, email, and domain from an address header."""
        if not header_value:
            return EmailAddressInfo()
        name, addr = parseaddr(str(header_value))
        addr = addr.strip("<>").strip()
        domain = addr.split("@")[-1].lower() if "@" in addr else ""
        return EmailAddressInfo(
            display_name=name.strip(),
            email=addr,
            domain=domain
        )

    @classmethod
    def _parse_address_list(cls, header_values: List[Any]) -> List[EmailAddressInfo]:
        """Extract a list of addresses from headers like To, CC, BCC."""
        if not header_values:
            return []
        
        raw_strs = []
        for val in header_values:
            if isinstance(val, list):
                raw_strs.extend([str(v) for v in val])
            else:
                raw_strs.append(str(val))
        
        parsed_tuples = getaddresses(raw_strs)
        results = []
        for name, addr in parsed_tuples:
            addr = addr.strip("<>").strip()
            if addr:
                domain = addr.split("@")[-1].lower() if "@" in addr else ""
                results.append(EmailAddressInfo(
                    display_name=name.strip(),
                    email=addr,
                    domain=domain
                ))
        return results

    @classmethod
    def _parse_received_headers(cls, received_headers: List[Any]) -> List[ReceivedHop]:
        """
        Parse Received headers into chronological hops.
        In standard emails, Received headers are stacked in reverse order
        (top is the recipient mail server, bottom is the earliest sender hop).
        We parse and number them from origin (1) to final recipient (N).
        """
        if not received_headers:
            return []

        # Reverse list so hop 1 is earliest sender hop
        raw_list = [str(r).strip() for r in reversed(received_headers) if str(r).strip()]
        hops: List[ReceivedHop] = []

        for idx, raw in enumerate(raw_list, start=1):
            hop = cls._parse_single_received_header(idx, raw)
            hops.append(hop)

        return hops

    @classmethod
    def _parse_single_received_header(cls, hop_idx: int, raw_header: str) -> ReceivedHop:
        """Parse individual Received header tokens."""
        clean_raw = " ".join(raw_header.split())
        
        # Regex patterns for Received header components
        from_match = re.search(r'from\s+([^\s;]+(?:\s+\([^)]+\))?)', clean_raw, re.IGNORECASE)
        by_match = re.search(r'by\s+([^\s;]+)', clean_raw, re.IGNORECASE)
        with_match = re.search(r'with\s+([^\s;]+)', clean_raw, re.IGNORECASE)
        
        # Extract IP address inside the header
        ip_matches = IPV4_REGEX.findall(clean_raw)
        hop_ip = ip_matches[0] if ip_matches else None
        
        # Timestamp usually follows the semicolon
        timestamp = None
        if ";" in clean_raw:
            ts_part = clean_raw.split(";")[-1].strip()
            try:
                dt = dateutil.parser.parse(ts_part)
                timestamp = dt.isoformat()
            except Exception:
                timestamp = ts_part

        ip_is_pub = False
        if hop_ip:
            classification = classify_ip(hop_ip)
            ip_is_pub = classification.get("is_public", False)

        from_host = from_match.group(1) if from_match else None
        by_host = by_match.group(1) if by_match else None
        protocol = with_match.group(1) if with_match else None

        return ReceivedHop(
            hop_number=hop_idx,
            from_host=from_host,
            by_host=by_host,
            ip=hop_ip,
            ip_is_public=ip_is_pub,
            timestamp=timestamp,
            protocol=protocol,
            raw_header=clean_raw,
            confidence=0.9
        )

    @classmethod
    def _determine_earliest_source_ip(cls, hops: List[ReceivedHop]) -> Optional[str]:
        """
        Determine the probable earliest visible source IP using transparent heuristics:
        1. Look from hop 1 onwards for the first valid public IP.
        2. If none are public, fallback to the earliest hop IP.
        """
        for hop in hops:
            if hop.ip and hop.ip_is_public:
                return hop.ip
        # If no public IP found, return first IP observed
        for hop in hops:
            if hop.ip:
                return hop.ip
        return None

    @classmethod
    def _parse_authentication_headers(cls, msg: Any, raw_headers: Dict[str, Any]) -> AuthenticationStatus:
        """
        Extract SPF, DKIM, and DMARC results from available security headers:
        - Authentication-Results
        - Received-SPF
        - DKIM-Signature
        - X-Authentication-Results
        """
        auth_results = msg.get("Authentication-Results", "") or msg.get("X-Authentication-Results", "")
        received_spf = msg.get("Received-SPF", "")
        dkim_sig = msg.get("DKIM-Signature", "")

        spf_res = "NONE"
        spf_details = None
        dkim_res = "NONE"
        dkim_details = None
        dmarc_res = "NONE"
        dmarc_details = None

        # Parse Authentication-Results header
        if auth_results:
            auth_str = str(auth_results).lower()
            
            # SPF in auth_results
            if "spf=pass" in auth_str:
                spf_res = "PASS"
                spf_details = "Header indicates SPF authentication passed."
            elif "spf=fail" in auth_str:
                spf_res = "FAIL"
                spf_details = "Header indicates SPF authentication failed."
            elif "spf=softfail" in auth_str:
                spf_res = "SOFTFAIL"
                spf_details = "Header indicates SPF softfail."
            elif "spf=neutral" in auth_str:
                spf_res = "NEUTRAL"
                spf_details = "Header indicates SPF neutral result."

            # DKIM in auth_results
            if "dkim=pass" in auth_str:
                dkim_res = "PASS"
                dkim_details = "Header indicates DKIM signature passed."
            elif "dkim=fail" in auth_str:
                dkim_res = "FAIL"
                dkim_details = "Header indicates DKIM signature failed."

            # DMARC in auth_results
            if "dmarc=pass" in auth_str:
                dmarc_res = "PASS"
                dmarc_details = "Header indicates DMARC verification passed."
            elif "dmarc=fail" in auth_str:
                dmarc_res = "FAIL"
                dmarc_details = "Header indicates DMARC policy check failed."

        # Parse Received-SPF fallback
        if spf_res == "NONE" and received_spf:
            spf_str = str(received_spf).lower()
            if spf_str.startswith("pass") or "pass" in spf_str[:20]:
                spf_res = "PASS"
                spf_details = str(received_spf)
            elif spf_str.startswith("fail") or "fail" in spf_str[:20]:
                spf_res = "FAIL"
                spf_details = str(received_spf)
            elif "softfail" in spf_str:
                spf_res = "SOFTFAIL"
                spf_details = str(received_spf)
            elif "neutral" in spf_str:
                spf_res = "NEUTRAL"
                spf_details = str(received_spf)

        # Check DKIM-Signature presence if not recorded in Auth-Results
        if dkim_res == "NONE" and dkim_sig:
            dkim_res = "UNVERIFIED_SIGNATURE_PRESENT"
            dkim_details = "DKIM-Signature header present (cryptographic verification required)."

        return AuthenticationStatus(
            spf_result=spf_res,
            spf_details=spf_details,
            dkim_result=dkim_res,
            dkim_details=dkim_details,
            dmarc_result=dmarc_res,
            dmarc_details=dmarc_details,
            raw_auth_results=str(auth_results) if auth_results else None,
            raw_dkim_signature=str(dkim_sig) if dkim_sig else None,
            raw_spf=str(received_spf) if received_spf else None
        )

    @classmethod
    def _extract_content_and_attachments(cls, msg: Any) -> Tuple[str, str, List[AttachmentInfo]]:
        """Safely extract plain text body, HTML body, and file attachments with forensic hashes."""
        body_text_parts = []
        body_html_parts = []
        attachments: List[AttachmentInfo] = []

        for part in msg.walk():
            # Check if part is an attachment
            content_disposition = str(part.get("Content-Disposition", ""))
            content_type = str(part.get_content_type())
            filename = part.get_filename()

            is_attachment = (
                "attachment" in content_disposition.lower() or
                (filename is not None and len(filename.strip()) > 0)
            )

            if is_attachment:
                try:
                    payload = part.get_payload(decode=True)
                    if payload is not None:
                        sha256_hash, md5_hash = compute_hashes(payload)
                        fname = filename or "unnamed_attachment"
                        ext = ("." + fname.split(".")[-1].lower()) if "." in fname else ""
                        
                        reasons = []
                        is_suspicious = False
                        
                        # Check dangerous extensions
                        if ext in SUSPICIOUS_ATTACHMENT_EXTENSIONS:
                            is_suspicious = True
                            reasons.append(f"Executable/script attachment extension '{ext}'.")
                        
                        # Check double extension like invoice.pdf.exe
                        parts_ext = fname.split(".")
                        if len(parts_ext) > 2 and parts_ext[-1].lower() in {"exe", "scr", "js", "vbs", "bat", "cmd", "ps1"}:
                            is_suspicious = True
                            reasons.append(f"Suspicious double extension detected in '{fname}'.")

                        attachments.append(AttachmentInfo(
                            filename=fname,
                            content_type=content_type,
                            size_bytes=len(payload),
                            sha256_hash=sha256_hash,
                            md5_hash=md5_hash,
                            extension=ext,
                            is_suspicious=is_suspicious,
                            suspicion_reasons=reasons
                        ))
                except Exception:
                    continue
            else:
                # Text or HTML content
                if content_type == "text/plain":
                    try:
                        text_content = part.get_content()
                        if isinstance(text_content, str):
                            body_text_parts.append(text_content)
                        elif isinstance(text_content, bytes):
                            body_text_parts.append(text_content.decode("utf-8", errors="replace"))
                    except Exception:
                        try:
                            raw = part.get_payload(decode=True)
                            if raw:
                                body_text_parts.append(raw.decode("utf-8", errors="replace"))
                        except Exception:
                            pass
                elif content_type == "text/html":
                    try:
                        html_content = part.get_content()
                        if isinstance(html_content, str):
                            body_html_parts.append(html_content)
                        elif isinstance(html_content, bytes):
                            body_html_parts.append(html_content.decode("utf-8", errors="replace"))
                    except Exception:
                        try:
                            raw = part.get_payload(decode=True)
                            if raw:
                                body_html_parts.append(raw.decode("utf-8", errors="replace"))
                        except Exception:
                            pass

        full_body_text = "\n\n".join(body_text_parts)
        full_body_html = "\n\n".join(body_html_parts)

        # If body_text is empty but HTML exists, extract clean text from HTML
        if not full_body_text and full_body_html:
            try:
                soup = BeautifulSoup(full_body_html, "html.parser")
                full_body_text = soup.get_text(separator="\n").strip()
            except Exception:
                pass

        return full_body_text, full_body_html, attachments

    @classmethod
    def _extract_urls(cls, body_text: str, body_html: str) -> List[Any]:
        """Extract and structure all unique URLs from plain text and HTML hyperlinks."""
        extracted_dict: Dict[str, Any] = {}

        # 1. Extract from HTML anchor tags with context
        if body_html:
            try:
                soup = BeautifulSoup(body_html, "html.parser")
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"].strip()
                    if href.startswith("http://") or href.startswith("https://"):
                        anchor_text = a_tag.get_text(strip=True) or None
                        if href not in extracted_dict:
                            parsed_url = parse_url_intelligence(href, context_text=anchor_text)
                            extracted_dict[href] = parsed_url
            except Exception:
                pass

        # 2. Extract from plain text
        if body_text:
            matches = URL_REGEX.findall(body_text)
            for m in matches:
                clean_url = m.rstrip(".,;)>'\"]")
                if clean_url not in extracted_dict:
                    parsed_url = parse_url_intelligence(clean_url, context_text="Plaintext body URL")
                    extracted_dict[clean_url] = parsed_url

        from app.schemas.intelligence import URLIntelligenceData
        return [URLIntelligenceData(**data) for data in extracted_dict.values()]
