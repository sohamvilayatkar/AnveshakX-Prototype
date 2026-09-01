import re
from bs4 import BeautifulSoup
from typing import Optional


class TextCleaner:
    """
    Deterministic Text Preprocessing Pipeline for Cybersecurity & Threat Intelligence:
    Extracts visible text, removes scripts/styles, strips markup safely,
    and preserves critical forensic keywords.
    """

    @classmethod
    def extract_clean_text(cls, subject: str = "", body_text: str = "", body_html: str = "") -> str:
        text_parts = []

        # 1. Clean Subject
        if subject:
            text_parts.append(cls._clean_raw_text(subject))

        # 2. Extract from plain-text body if available
        if body_text and body_text.strip():
            text_parts.append(cls._clean_raw_text(body_text))
        elif body_html and body_html.strip():
            # Extract plain text safely from HTML
            try:
                soup = BeautifulSoup(body_html, "html.parser")
                # Remove scripts and styling elements
                for element in soup(["script", "style", "meta", "link", "noscript"]):
                    element.extract()
                raw_extracted = soup.get_text(separator=" ")
                text_parts.append(cls._clean_raw_text(raw_extracted))
            except Exception:
                text_parts.append(cls._clean_raw_text(body_html))

        combined = " ".join(text_parts).strip()
        return combined

    @classmethod
    def _clean_raw_text(cls, raw: str) -> str:
        if not raw:
            return ""

        # Normalize line endings
        text = raw.replace("\r\n", " ").replace("\n", " ").replace("\t", " ")

        # Replace URLs with token while preserving domain tokens
        text = re.sub(r'https?://[^\s/$.?#].[^\s]*', ' url_link ', text)

        # Replace email addresses with token
        text = re.sub(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', ' email_addr ', text)

        # Remove non-alphanumeric punctuation except currency symbols ($ € £) and dashes
        text = re.sub(r'[^a-zA-Z0-9\$\€\£\s\-]', ' ', text)

        # Collapse multiple spaces
        text = re.sub(r'\s+', ' ', text)

        return text.strip().lower()
