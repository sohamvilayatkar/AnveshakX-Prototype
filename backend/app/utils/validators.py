import os
from typing import Tuple
from app.config import settings

ALLOWED_EXTENSIONS = {".eml", ".msg", ".txt"}
ALLOWED_MIME_TYPES = {
    "message/rfc822",
    "text/plain",
    "application/octet-stream",
    "message/news",
    "application/x-download",
    "multipart/mixed",
    "text/rfc822-headers"
}


def validate_email_file(filename: str, content_type: str, file_size: int) -> Tuple[bool, str]:
    """Validate uploaded email file for format and size limits."""
    # Check file size
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if file_size > max_bytes:
        return False, f"File size ({file_size / (1024*1024):.2f} MB) exceeds maximum limit of {settings.MAX_UPLOAD_SIZE_MB} MB."

    if file_size == 0:
        return False, "Uploaded file is empty (0 bytes)."

    # Check extension
    _, ext = os.path.splitext(filename.lower())
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Invalid file extension '{ext}'. Only .eml, .msg, or .txt files are supported."

    return True, "Valid"
