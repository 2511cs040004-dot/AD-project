"""
AEGISTID - Cryptographic Integrity & Hashing Module
Calculates chunked SHA-256 cryptographic hashes for uploaded documents,
enabling immutable integrity verification and tamper tracking.
"""

import hashlib
import os
from pathlib import Path


def calculate_sha256(file_path: str) -> str:
    """
    Computes SHA-256 hex digest for a file using memory-efficient 64KB chunks.

    Args:
        file_path (str): Path to file.

    Returns:
        str: 64-character lowercase hexadecimal SHA-256 hash digest.
    """
    file_path = Path(file_path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found for hashing: {file_path}")

    sha256 = hashlib.sha256()
    with open(file_path, "rb") as fp:
        for chunk in iter(lambda: fp.read(65536), b""):
            sha256.update(chunk)

    return sha256.hexdigest().lower()


def verify_sha256(file_path: str, expected_hash: str) -> bool:
    """
    Verifies whether a file matches an expected SHA-256 hash digest.
    """
    if not expected_hash:
        return False
    actual_hash = calculate_sha256(file_path)
    return actual_hash.strip().lower() == expected_hash.strip().lower()