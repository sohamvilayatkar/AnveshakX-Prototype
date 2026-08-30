import re
from typing import Dict, Any, List, Optional, Tuple
from app.utils.domain_utils import extract_domain_info

# Configurable protected target brands list
DEFAULT_PROTECTED_BRANDS: Dict[str, List[str]] = {
    "SBI": ["sbi.co.in", "onlinesbi.sbi", "statebankofindia.com"],
    "HDFC Bank": ["hdfcbank.com", "hdfc.com"],
    "ICICI Bank": ["icicibank.com"],
    "Axis Bank": ["axisbank.com"],
    "Microsoft": ["microsoft.com", "office.com", "office365.com", "live.com", "outlook.com", "azure.com"],
    "Google": ["google.com", "gmail.com", "googlemail.com"],
    "Apple": ["apple.com", "icloud.com"],
    "Amazon": ["amazon.com", "amazon.in", "aws.amazon.com"],
    "PayPal": ["paypal.com", "paypal.me"]
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute standard Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def jaro_similarity(s1: str, s2: str) -> float:
    """Compute Jaro string similarity (0.0 to 1.0)."""
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0

    match_distance = max(len1, len2) // 2 - 1
    s1_matches = [False] * len1
    s2_matches = [False] * len2
    matches = 0
    transpositions = 0

    for i in range(len1):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len2)
        for j in range(start, end):
            if s2_matches[j]:
                continue
            if s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break

    if matches == 0:
        return 0.0

    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1

    return ((matches / len1) + (matches / len2) + ((matches - transpositions / 2) / matches)) / 3.0


class ImpersonationDetector:
    """
    Lookalike & Brand Impersonation Forensics:
    Detects typosquatting, combisquatting, character substitutions (e.g. micros0ft),
    and suspicious target-brand mimics in domains.
    """

    @classmethod
    def check_domain(
        cls,
        observed_domain: str,
        protected_brands: Optional[Dict[str, List[str]]] = None
    ) -> Dict[str, Any]:
        """
        Check if an observed domain resembles any brand in the protected brands dictionary.
        Returns lookalike detection status, target brand, similarity metric, and reasons.
        """
        if not observed_domain:
            return {"is_impersonation": False, "target_brand": None, "confidence": 0.0, "reasons": []}

        brands = protected_brands or DEFAULT_PROTECTED_BRANDS
        domain_info = extract_domain_info(observed_domain)
        reg_domain = domain_info["registered_domain"].lower()
        subdomain = domain_info["subdomain"].lower()
        full_name = f"{subdomain}.{reg_domain}" if subdomain else reg_domain

        # Extract root stem (e.g., 'sbi-secure-portal' from 'sbi-secure-portal.xyz')
        observed_stem = reg_domain.split(".")[0] if "." in reg_domain else reg_domain

        best_match_brand = None
        highest_similarity = 0.0
        reasons = []

        # Common leetspeak / number substitutions (e.g., '0' for 'o', '1' for 'l'/'i')
        normalized_stem = (
            observed_stem
            .replace("0", "o")
            .replace("1", "l")
            .replace("3", "e")
            .replace("5", "s")
            .replace("@", "a")
            .replace("-", "")
        )

        for brand_name, legitimate_domains in brands.items():
            for leg_domain in legitimate_domains:
                # If it's an exact legitimate domain, it is NOT an impersonation
                if reg_domain == leg_domain.lower():
                    return {
                        "is_impersonation": False,
                        "target_brand": None,
                        "confidence": 0.0,
                        "reasons": []
                    }

                leg_stem = leg_domain.split(".")[0]
                
                # 1. Check direct brand token containment (Combisquatting: sbi-secure-login, microsoft-support)
                if brand_name.lower().replace(" ", "") in observed_stem or leg_stem in observed_stem or leg_stem in normalized_stem:
                    if domain_info["is_suspicious_tld"] or "-" in observed_stem or len(observed_stem) > len(leg_stem):
                        confidence = 0.88 if domain_info["is_suspicious_tld"] else 0.78
                        reasons.append(f"Domain stem '{observed_stem}' contains protected brand token '{brand_name}' with combisquatting pattern.")
                        return {
                            "is_impersonation": True,
                            "target_brand": brand_name,
                            "legitimate_domain": leg_domain,
                            "confidence": confidence,
                            "similarity_score": 0.90,
                            "reasons": reasons,
                            "message": f"Possible brand impersonation: observed domain resembles {brand_name} ({leg_domain})."
                        }

                # 2. Check Levenshtein & Jaro similarity on domain stem
                lev = levenshtein_distance(normalized_stem, leg_stem)
                jaro = jaro_similarity(normalized_stem, leg_stem)

                if (lev in (1, 2) and len(leg_stem) >= 4) or jaro > 0.85:
                    sim = round(jaro, 3)
                    if sim > highest_similarity:
                        highest_similarity = sim
                        best_match_brand = (brand_name, leg_domain, f"Typographical similarity (edit distance={lev}, Jaro={sim}) against '{leg_stem}'.")

        if best_match_brand:
            brand_name, leg_domain, reason_text = best_match_brand
            return {
                "is_impersonation": True,
                "target_brand": brand_name,
                "legitimate_domain": leg_domain,
                "confidence": round(highest_similarity, 2),
                "similarity_score": highest_similarity,
                "reasons": [reason_text],
                "message": f"Possible lookalike domain: resembles legitimate organization {brand_name} ({leg_domain})."
            }

        return {
            "is_impersonation": False,
            "target_brand": None,
            "confidence": 0.0,
            "similarity_score": 0.0,
            "reasons": []
        }
