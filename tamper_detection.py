"""
AEGISTID - AI Tamper Detection & Forensic Screening Module
Analyzes document images for digital manipulation, copy-paste alterations,
and localized re-compression inconsistencies using Error Level Analysis (ELA)
and local edge variance heuristics.
"""

import os
import uuid
from pathlib import Path
import numpy as np
from PIL import Image, ImageChops, ImageEnhance
import cv2

BASE_DIR = Path(__file__).resolve().parent
PROCESSED_DIR = BASE_DIR / "processed"
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)


def compute_edge_noise_variance(image_path: str) -> dict:
    """
    Splits image into a grid and computes Laplacian edge variance
    to detect spliced patches or abnormally sharp text overlays.
    """
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        return {"anomaly_detected": False, "variance_ratio": 1.0}

    h, w = img.shape
    grid_rows, grid_cols = 4, 4
    h_step = h // grid_rows
    w_step = w // grid_cols

    variances = []
    for r in range(grid_rows):
        for c in range(grid_cols):
            patch = img[r * h_step:(r + 1) * h_step, c * w_step:(c + 1) * w_step]
            if patch.size > 0:
                lap = cv2.Laplacian(patch, cv2.CV_64F)
                variances.append(lap.var())

    if not variances:
        return {"anomaly_detected": False, "variance_ratio": 1.0}

    v_min = min(variances)
    v_max = max(variances)
    ratio = (v_max / (v_min + 1e-5))

    return {
        "anomaly_detected": ratio > 18.0,
        "max_variance": round(v_max, 2),
        "min_variance": round(v_min, 2),
        "variance_ratio": round(ratio, 2),
    }


def detect_tampering(image_path: str) -> dict:
    """
    Performs forensic image tampering screening:
    1. Error Level Analysis (ELA) to expose differing JPEG compression levels.
    2. Local frequency and edge variance analysis to detect spliced inserts.
    3. Clearly labels heuristic findings vs trained deep-learning models.

    Args:
        image_path (str): Path to document image.

    Returns:
        dict: Forensic screening report including ELA metrics, visualization path,
              verdict, and methodology disclosure.
    """
    image_path = os.path.abspath(os.fspath(image_path))
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Document for tamper detection not found: {image_path}")

    # 1. Error Level Analysis (ELA)
    original = Image.open(image_path).convert("RGB")

    unique_id = uuid.uuid4().hex
    temp_jpeg = PROCESSED_DIR / f"temp_{unique_id}.jpg"

    # Resave at fixed 90% JPEG quality
    original.save(temp_jpeg, "JPEG", quality=90)
    compressed = Image.open(temp_jpeg).convert("RGB")

    # Compute difference
    diff = ImageChops.difference(original, compressed)

    # Enhance difference contrast (scale 12x) for human audit visibility
    enhancer = ImageEnhance.Brightness(diff)
    ela_enhanced = enhancer.enhance(12.0)

    ela_filename = f"ela_{unique_id}.jpg"
    ela_output_path = PROCESSED_DIR / ela_filename
    ela_enhanced.save(ela_output_path, "JPEG", quality=95)

    # Clean up temporary resaved JPEG
    if temp_jpeg.is_file():
        try:
            os.remove(temp_jpeg)
        except OSError:
            pass

    # Calculate difference metrics
    diff_arr = np.array(diff, dtype=np.float32)
    max_diff = float(np.max(diff_arr))
    mean_diff = float(np.mean(diff_arr))
    std_diff = float(np.std(diff_arr))

    # 2. Edge / noise anomaly analysis
    edge_analysis = compute_edge_noise_variance(image_path)

    # Threshold evaluation
    # High max difference (>45) along with high standard deviation (>8) indicates localized alteration
    ela_anomaly = (max_diff > 45.0 and std_diff > 7.5) or (mean_diff > 12.0)
    edge_anomaly = edge_analysis.get("anomaly_detected", False)

    is_tampered = ela_anomaly or edge_anomaly

    if ela_anomaly and edge_anomaly:
        confidence = "Elevated"
        message = "Elevated tampering risk: High compression discrepancy and edge noise variance detected."
    elif ela_anomaly:
        confidence = "Moderate"
        message = "Potential localized modification detected via Error Level Analysis (ELA)."
    elif edge_anomaly:
        confidence = "Low"
        message = "Uneven edge sharpness detected across document sectors."
    else:
        confidence = "Clean"
        message = "No abnormal compression artifacts or tampering indicators detected."

    return {
        "tampered": is_tampered,
        "difference": round(max_diff, 2),
        "mean_difference": round(mean_diff, 2),
        "std_difference": round(std_diff, 2),
        "edge_analysis": edge_analysis,
        "confidence": confidence,
        "message": message,
        "ela_image": ela_filename,
        "ela_path": str(ela_output_path.resolve()),
        "analysis_type": "Computer Vision Heuristics (ELA + Edge Variance)",
        "disclaimer": "Heuristic forensic indicator; does not constitute certified proof of origin.",
    }