"""
AEGISTID - Image Preprocessing Module
Performs orientation correction, resizing, contrast enhancement (LAB CLAHE),
noise reduction, and image normalization for high-accuracy document screening.
"""

import os
import uuid
from pathlib import Path
import cv2
import numpy as np
import pytesseract

BASE_DIR = Path(__file__).resolve().parent
PROCESSED_DIR = BASE_DIR / "processed"
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

# Tesseract OCR executable configuration
TESSERACT_CANDIDATES = [
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
    r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    r"C:\Users\LENOVO\AppData\Local\Programs\Tesseract-OCR\tesseract.exe",
]

for candidate in TESSERACT_CANDIDATES:
    if os.path.isfile(candidate):
        pytesseract.pytesseract.tesseract_cmd = candidate
        break


def rotate_image(image, angle):
    """Rotate an image clockwise by 0, 90, 180, or 270 degrees."""
    if angle == 90:
        return cv2.rotate(image, cv2.ROTATE_90_CLOCKWISE)
    if angle == 180:
        return cv2.rotate(image, cv2.ROTATE_180)
    if angle == 270:
        return cv2.rotate(image, cv2.ROTATE_90_COUNTERCLOCKWISE)
    return image


def score_text(text):
    """Score extracted OCR text based on identity document tokens and patterns."""
    if not text:
        return 0

    text_upper = text.upper()
    score = 0

    keywords = [
        "PASSPORT",
        "REPUBLIC",
        "INDIA",
        "GOVERNMENT",
        "NATIONALITY",
        "SURNAME",
        "GIVEN",
        "NAME",
        "DATE OF BIRTH",
        "DATE OF EXPIRY",
        "AADHAAR",
        "AADHAR",
        "IDENTITY",
        "UNION",
        "P<IND",
    ]

    for kw in keywords:
        if kw in text_upper:
            score += 15

    # Check for MRZ chevron sequences (e.g., P<IND or <<<<)
    if "<<" in text:
        score += 30

    # Digits count
    digits = sum(c.isdigit() for c in text)
    if digits >= 8:
        score += 10
    if digits >= 16:
        score += 15

    return score


def detect_best_orientation(image):
    """
    Evaluates 0, 90, 180, and 270 degree orientations using fast OCR heuristics.
    Returns the optimally oriented image and angle.
    """
    best_image = image
    best_angle = 0
    best_score = -1

    # Resize down temporarily for super-fast orientation check
    h, w = image.shape[:2]
    max_dim = max(h, w)
    scale = min(1.0, 900 / max_dim)
    small = cv2.resize(image, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)

    for angle in [0, 90, 180, 270]:
        rotated = rotate_image(small, angle)
        gray = cv2.cvtColor(rotated, cv2.COLOR_BGR2GRAY)

        try:
            text = pytesseract.image_to_string(
                gray,
                config="--psm 6 --oem 3"
            )
            score = score_text(text)
        except Exception as exc:
            print(f"[AEGISTID Preprocessing] Orientation OCR notice: {exc}")
            return image, 0

        print(f"[AEGISTID Preprocessing] Orientation {angle}° score: {score}")
        if score > best_score:
            best_score = score
            best_angle = angle

    print(f"[AEGISTID Preprocessing] Selected orientation: {best_angle}° (Score: {best_score})")
    if best_angle != 0:
        return rotate_image(image, best_angle), best_angle
    return image, 0


def preprocess_document(input_path):
    """
    Comprehensive document preprocessing:
    1. Loads image securely.
    2. Corrects document rotation.
    3. Normalizes aspect ratio and scales up to 1600px.
    4. Applies LAB CLAHE contrast enhancement for enhanced sharpness without losing color.
    5. Cleans noise while keeping text edges crisp.
    6. Saves to processed/ with unique filename.

    Returns:
        str: Absolute path to the processed image.
    """
    input_path = os.path.abspath(os.fspath(input_path))
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Uploaded document does not exist: {input_path}")

    image = cv2.imread(input_path, cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError("OpenCV cannot read this image. Invalid or corrupt file.")

    # 1. Orientation detection and rotation
    try:
        image, applied_angle = detect_best_orientation(image)
    except Exception as exc:
        print(f"[AEGISTID Preprocessing] Skipping orientation detection: {exc}")
        applied_angle = 0

    # 2. Scale image (limit longest side to 1800px for balance between detail & speed)
    height, width = image.shape[:2]
    longest = max(width, height)
    if longest > 1800:
        scale = 1800.0 / longest
        image = cv2.resize(image, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)
    elif longest < 700:
        # Upscale small images to improve OCR and face detection
        scale = 1200.0 / longest
        image = cv2.resize(image, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)

    # 3. Enhance contrast in LAB color space (preserves natural portrait & ink colors)
    lab = cv2.cvtColor(image, cv2.COLOR_BGR2LAB)
    l_channel, a_channel, b_channel = cv2.split(lab)

    clahe = cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8, 8))
    cl = clahe.apply(l_channel)

    # Mild denoising on lightness channel
    cl = cv2.GaussianBlur(cl, (3, 3), 0)

    # Merge enhanced L channel back with color channels
    enhanced_lab = cv2.merge((cl, a_channel, b_channel))
    enhanced_bgr = cv2.cvtColor(enhanced_lab, cv2.COLOR_LAB2BGR)

    # Mild unsharp mask for razor-sharp text
    gaussian = cv2.GaussianBlur(enhanced_bgr, (0, 0), 2.0)
    sharpened = cv2.addWeighted(enhanced_bgr, 1.35, gaussian, -0.35, 0)

    # 4. Save processed image
    unique_name = f"processed_{uuid.uuid4().hex}.jpg"
    output_path = PROCESSED_DIR / unique_name

    saved = cv2.imwrite(
        str(output_path),
        sharpened,
        [cv2.IMWRITE_JPEG_QUALITY, 96]
    )

    if not saved or not output_path.is_file():
        raise IOError(f"Failed to write processed image: {output_path}")

    print(f"[AEGISTID Preprocessing] Successfully processed image: {output_path} ({sharpened.shape[1]}x{sharpened.shape[0]})")
    return str(output_path.resolve())
