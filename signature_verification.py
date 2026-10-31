"""
AEGISTID - Signature Analysis & Verification Module
Supports dual-mode signature analysis:
1. One-to-one comparative verification against an uploaded reference signature
   using adaptive thresholding, contour area matching, and normalized cross-correlation.
2. In-document signature zone localization and extraction when no reference signature is provided.
"""

import os
import uuid
from pathlib import Path
import cv2
import numpy as np

BASE_DIR = Path(__file__).resolve().parent
PROCESSED_DIR = BASE_DIR / "processed"
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)


def load_signature(path: str):
    """Loads signature image in grayscale."""
    img = cv2.imread(str(path), cv2.IMREAD_GRAYSCALE)
    if img is None:
        raise ValueError(f"Unable to read signature image: {path}")
    return img


def preprocess_signature(image):
    """Normalizes signature image with adaptive thresholding and noise removal."""
    resized = cv2.resize(image, (500, 200), interpolation=cv2.INTER_AREA)
    blurred = cv2.GaussianBlur(resized, (3, 3), 0)
    binary = cv2.adaptiveThreshold(
        blurred,
        255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY_INV,
        31,
        10,
    )
    kernel = np.ones((2, 2), np.uint8)
    opened = cv2.morphologyEx(binary, cv2.MORPH_OPEN, kernel)
    return opened


def crop_signature(binary):
    """Borders and crops signature strokes to its bounding content."""
    points = cv2.findNonZero(binary)
    if points is None:
        return binary

    x, y, w, h = cv2.boundingRect(points)
    padding = 10
    x1 = max(0, x - padding)
    y1 = max(0, y - padding)
    x2 = min(binary.shape[1], x + w + padding)
    y2 = min(binary.shape[0], y + h + padding)

    cropped = binary[y1:y2, x1:x2]
    return cropped


def normalize_signature(binary):
    """Crops and standardizes signature dimensions."""
    cropped = crop_signature(binary)
    if cropped.size == 0:
        return np.zeros((200, 500), dtype=np.uint8)
    return cv2.resize(cropped, (500, 200), interpolation=cv2.INTER_AREA)


def pixel_similarity(sig1, sig2):
    """Calculates pixel-wise stroke alignment."""
    diff = cv2.absdiff(sig1, sig2)
    diff_score = np.mean(diff)
    sim = 100.0 - (diff_score / 255.0 * 100.0)
    return max(0.0, min(100.0, sim))


def contour_similarity(sig1, sig2):
    """Compares primary contour geometry and stroke mass."""
    contours1, _ = cv2.findContours(sig1, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    contours2, _ = cv2.findContours(sig2, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

    if not contours1 or not contours2:
        return 0.0

    large1 = max(contours1, key=cv2.contourArea)
    large2 = max(contours2, key=cv2.contourArea)

    a1 = cv2.contourArea(large1)
    a2 = cv2.contourArea(large2)

    if a1 <= 0 or a2 <= 0:
        return 0.0

    ratio = min(a1, a2) / max(a1, a2)
    return float(ratio * 100.0)


def correlation_similarity(sig1, sig2):
    """Computes Pearson normalized cross-correlation of signature matrices."""
    f1 = sig1.astype(np.float32)
    f2 = sig2.astype(np.float32)

    m1 = np.mean(f1)
    m2 = np.mean(f2)

    num = np.sum((f1 - m1) * (f2 - m2))
    denom = np.sqrt(np.sum((f1 - m1) ** 2) * np.sum((f2 - m2) ** 2))

    if denom == 0:
        return 0.0

    corr = num / denom
    # Scale from [-1, 1] to [0, 100]
    return float(((corr + 1.0) / 2.0) * 100.0)


def calculate_signature_similarity(sig1, sig2):
    """Weighted composite similarity score."""
    p_score = pixel_similarity(sig1, sig2)
    c_score = contour_similarity(sig1, sig2)
    corr_score = correlation_similarity(sig1, sig2)

    # 40% pixel, 20% contour, 40% normalized correlation
    total = (p_score * 0.40) + (c_score * 0.20) + (corr_score * 0.40)
    return round(total, 2)


def extract_signature_candidate(document_path: str):
    """
    Attempts to extract the signature bounding box from the document's signature band.
    """
    img = cv2.imread(str(document_path))
    if img is None:
        return None

    h, w = img.shape[:2]
    # Signature is typically in the lower 45% of an ID or passport page
    start_y = int(h * 0.50)
    region = img[start_y:h, 0:w]

    gray = cv2.cvtColor(region, cv2.COLOR_BGR2GRAY)
    blurred = cv2.GaussianBlur(gray, (3, 3), 0)
    _, binary = cv2.threshold(blurred, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)

    kernel = np.ones((2, 2), np.uint8)
    binary = cv2.morphologyEx(binary, cv2.MORPH_OPEN, kernel)

    contours, _ = cv2.findContours(binary, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    candidates = []

    for c in contours:
        x, y, cw, ch = cv2.boundingRect(c)
        area = cw * ch
        if area > 450 and cw > 60 and ch > 15:
            aspect = cw / float(ch)
            if 1.2 <= aspect <= 15.0:
                candidates.append((area, x, y, cw, ch))

    if not candidates:
        return None

    # Pick largest plausible stroke region
    candidates.sort(reverse=True)
    _, x, y, cw, ch = candidates[0]

    pad = 15
    x1 = max(0, x - pad)
    y1 = max(0, y - pad)
    x2 = min(region.shape[1], x + cw + pad)
    y2 = min(region.shape[0], y + ch + pad)

    sig_crop = region[y1:y2, x1:x2]
    if sig_crop.size == 0:
        return None

    unique_name = f"extracted_sig_{uuid.uuid4().hex}.png"
    out_path = PROCESSED_DIR / unique_name
    cv2.imwrite(str(out_path), sig_crop)

    return unique_name


def verify_signature(document_path: str, reference_signature_path: str = None) -> dict:
    """
    Analyzes document signature.
    If reference_signature_path is provided: performs 1-to-1 comparison.
    If reference_signature_path is None: extracts signature region and flags matching as unavailable.
    """
    # Case 1: Comparative verification requested with reference file
    if reference_signature_path and os.path.isfile(reference_signature_path):
        try:
            doc_sig = load_signature(document_path)
            ref_sig = load_signature(reference_signature_path)

            doc_norm = normalize_signature(preprocess_signature(doc_sig))
            ref_norm = normalize_signature(preprocess_signature(ref_sig))

            sim = calculate_signature_similarity(doc_norm, ref_norm)
            threshold = 70.0
            verified = bool(sim >= threshold)

            message = (
                f"Signature match confirmed ({sim}% similarity exceeds {threshold}% threshold)."
                if verified
                else f"Signature discrepancy detected ({sim}% similarity is below {threshold}% threshold)."
            )

            return {
                "verified": verified,
                "reference_provided": True,
                "similarity": sim,
                "threshold": threshold,
                "matches": 1 if verified else 0,
                "message": message,
                "status": "Verified" if verified else "Mismatch",
            }
        except Exception as exc:
            return {
                "verified": False,
                "reference_provided": True,
                "error": str(exc),
                "message": f"Signature comparison failed: {exc}",
                "status": "Error",
            }

    # Case 2: No reference signature uploaded
    extracted_filename = None
    try:
        extracted_filename = extract_signature_candidate(document_path)
    except Exception as exc:
        print(f"[AEGISTID Signature] Extraction notice: {exc}")

    if extracted_filename:
        message = (
            "Signature zone extracted from document. "
            "1-to-1 comparison was not performed because no reference signature was provided."
        )
        status = "Zone Extracted (No Reference)"
    else:
        message = (
            "No reference signature provided. Automated extraction did not isolate a distinct standalone signature."
        )
        status = "Inconclusive (No Reference)"

    return {
        "verified": None,
        "reference_provided": False,
        "signature_extracted": bool(extracted_filename),
        "extracted_signature_image": extracted_filename,
        "status": status,
        "message": message,
        "disclaimer": "Signature matching requires a verified specimen image for 1:1 validation.",
    }