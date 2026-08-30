import hashlib
from typing import Tuple


def compute_sha256(data: bytes) -> str:
    """Compute standard hexadecimal SHA-256 hash for forensic evidence verification."""
    return hashlib.sha256(data).hexdigest()


def compute_md5(data: bytes) -> str:
    """Compute MD5 hash for secondary compatibility."""
    return hashlib.md5(data).hexdigest()


def compute_hashes(data: bytes) -> Tuple[str, str]:
    """Compute both SHA-256 and MD5 for complete forensic artifact tracking."""
    sha256_val = hashlib.sha256(data).hexdigest()
    md5_val = hashlib.md5(data).hexdigest()
    return sha256_val, md5_val


def compute_file_sha256(file_path: str) -> str:
    """Compute SHA-256 hash of a file on disk reading in 64KB chunks."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(65536), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()
