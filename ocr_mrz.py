"""
AEGISTID - OCR & MRZ Extraction Engine
Extracts full text and machine-readable zones (MRZ) from document credentials,
parses passport and ID card fields according to ICAO Doc 9303 standards,
and performs 7-3-1 weight check-digit algorithmic validation.
"""

import os
import re
from datetime import datetime
from pathlib import Path
import cv2
import pytesseract

BASE_DIR = Path(__file__).resolve().parent

TESSERACT_CANDIDATES = [
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
    r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    r"C:\Users\LENOVO\AppData\Local\Programs\Tesseract-OCR\tesseract.exe",
]

for candidate in TESSERACT_CANDIDATES:
    if os.path.isfile(candidate):
        pytesseract.pytesseract.tesseract_cmd = candidate
        break


# ============================================================
# ICAO 9303 CHECK DIGIT CALCULATION
# ============================================================

def icao_char_value(c: str) -> int:
    """Returns the ICAO Doc 9303 numeric value for a character."""
    c = c.upper()
    if c.isdigit():
        return int(c)
    if "A" <= c <= "Z":
        return ord(c) - ord("A") + 10
    return 0


def calculate_check_digit(data: str) -> str:
    """
    Computes ICAO Doc 9303 check digit with 7-3-1 repeating weighting:
    Sum(char_val * weight) modulo 10.
    """
    weights = [7, 3, 1]
    total = 0
    for idx, char in enumerate(data):
        total += icao_char_value(char) * weights[idx % 3]
    return str(total % 10)


def verify_check_digit(data: str, expected_digit: str) -> bool:
    """Compares calculated check digit with the expected check digit."""
    if not expected_digit or not expected_digit.isdigit():
        return False
    return calculate_check_digit(data) == expected_digit


# ============================================================
# IMAGE PREPARATION FOR HIGH-ACCURACY OCR
# ============================================================

def prepare_ocr_variations(image):
    """Generates multiple filtered versions of the document image to maximize OCR yield."""
    variations = []
    variations.append(("Standard", image))

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    variations.append(("Grayscale", gray))

    clahe = cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8, 8))
    enhanced = clahe.apply(gray)
    variations.append(("CLAHE", enhanced))

    _, otsu = cv2.threshold(enhanced, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    variations.append(("Otsu", otsu))

    adaptive = cv2.adaptiveThreshold(
        enhanced,
        255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY,
        31,
        11,
    )
    variations.append(("Adaptive", adaptive))

    return variations


def score_ocr_text(text: str) -> int:
    """Scores candidate text based on richness of identity keywords and MRZ tokens."""
    if not text:
        return 0

    text_upper = text.upper()
    score = 0

    keywords = [
        "PASSPORT", "REPUBLIC", "INDIA", "INDIAN", "NATIONALITY",
        "SURNAME", "GIVEN", "NAME", "DATE OF BIRTH", "DATE OF EXPIRY",
        "PLACE OF BIRTH", "PLACE OF ISSUE", "SEX", "MALE", "FEMALE",
        "GOVERNMENT", "AADHAAR", "IDENTITY", "DOCUMENT"
    ]

    for kw in keywords:
        if kw in text_upper:
            score += 12

    digits = sum(c.isdigit() for c in text)
    if digits >= 8:
        score += 10
    if digits >= 16:
        score += 15

    if "<<" in text:
        score += 35

    # Check for likely MRZ line length
    for line in text_upper.splitlines():
        clean = re.sub(r"[^A-Z0-9<]", "", line)
        if len(clean) in (30, 36, 44):
            score += 25

    return score


def extract_full_text(image_path: str) -> str:
    """Reads document and runs multi-pass OCR to obtain the highest quality text."""
    image = cv2.imread(image_path)
    if image is None:
        raise ValueError(f"Unable to load image for OCR: {image_path}")

    variations = prepare_ocr_variations(image)
    best_text = ""
    best_score = -1

    for name, img in variations:
        try:
            # Run page segmentation mode 6 (assume a single uniform block of text)
            text = pytesseract.image_to_string(img, config="--oem 3 --psm 6")
            text = text.strip()
            score = score_ocr_text(text)
            if score > best_score:
                best_score = score
                best_text = text
        except Exception as exc:
            print(f"[AEGISTID OCR] {name} pass notice: {exc}")

    # Fallback to default PSM if best_score is very low
    if best_score < 20:
        try:
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            text = pytesseract.image_to_string(gray, config="--oem 3 --psm 3")
            if score_ocr_text(text) > best_score:
                best_text = text
        except Exception:
            pass

    return best_text


# ============================================================
# MRZ EXTRACTION & ICAO 9303 PARSER
# ============================================================

def extract_mrz_lines(raw_text: str) -> list:
    """
    Extracts potential MRZ lines from raw text.
    Handles ICAO TD3 (2 lines x 44 chars) and TD1/TD2 (3 lines x 30/36 chars).
    """
    mrz_candidates = []

    for line in raw_text.splitlines():
        # Remove spaces and noise
        cleaned = re.sub(r"[^A-Z0-9<]", "", line.upper())
        if len(cleaned) >= 28:
            # Check ratio of valid MRZ characters
            mrz_ratio = sum(c.isalnum() or c == "<" for c in cleaned) / len(cleaned)
            if mrz_ratio >= 0.90:
                mrz_candidates.append(cleaned)

    # Return last 2 or 3 lines which correspond to the MRZ zone at the bottom of the card
    if len(mrz_candidates) >= 3 and all(len(c) in range(28, 38) for c in mrz_candidates[-3:]):
        return mrz_candidates[-3:]
    if len(mrz_candidates) >= 2:
        return mrz_candidates[-2:]

    return mrz_candidates


def parse_td3_mrz(line1: str, line2: str) -> dict:
    """
    Parses standard 2-line ICAO TD3 Passport MRZ (44 characters per line).
    """
    parsed = {
        "mrz_type": "TD3",
        "doc_type": "Passport",
        "issuing_state": None,
        "surname": None,
        "given_names": None,
        "full_name": None,
        "document_number": None,
        "nationality": None,
        "date_of_birth": None,
        "sex": None,
        "date_of_expiry": None,
        "checksums": {},
        "mrz_valid": True,
    }

    # Ensure padding to at least 44 characters
    l1 = line1.ljust(44, "<")[:44]
    l2 = line2.ljust(44, "<")[:44]

    # Line 1 parsing
    doc_code = l1[0:2].replace("<", "")
    if doc_code.startswith("P"):
        parsed["doc_type"] = "Passport"
    elif doc_code.startswith("V"):
        parsed["doc_type"] = "Visa"
    else:
        parsed["doc_type"] = "Identity Document"

    parsed["issuing_state"] = l1[2:5].replace("<", "")

    # Name section (after pos 5)
    name_section = l1[5:]
    if "<<" in name_section:
        parts = name_section.split("<<", 1)
        surname = parts[0].replace("<", " ").strip()
        given = parts[1].replace("<", " ").strip()
        parsed["surname"] = surname
        parsed["given_names"] = given
        parsed["full_name"] = f"{surname} {given}".strip()
    else:
        parsed["full_name"] = name_section.replace("<", " ").strip()

    # Line 2 parsing
    doc_num_raw = l2[0:9]
    doc_num = doc_num_raw.replace("<", "")
    doc_num_check = l2[9:10]

    nationality = l2[10:13].replace("<", "")
    dob_raw = l2[13:19]
    dob_check = l2[19:20]

    sex_char = l2[20:21]
    if sex_char == "M":
        sex = "Male"
    elif sex_char == "F":
        sex = "Female"
    else:
        sex = "Unspecified"

    expiry_raw = l2[21:27]
    expiry_check = l2[27:28]

    optional_data = l2[28:42]
    composite_check = l2[43:44]

    # Check digit validations
    doc_num_valid = verify_check_digit(doc_num_raw, doc_num_check)
    dob_valid = verify_check_digit(dob_raw, dob_check)
    expiry_valid = verify_check_digit(expiry_raw, expiry_check)

    # Composite check digit data string
    comp_data = l2[0:10] + l2[13:20] + l2[21:43]
    composite_valid = verify_check_digit(comp_data, composite_check)

    parsed["document_number"] = doc_num
    parsed["nationality"] = nationality
    parsed["sex"] = sex

    # Format dates
    try:
        # DOB: YYMMDD
        yy = int(dob_raw[0:2])
        mm = int(dob_raw[2:4])
        dd = int(dob_raw[4:6])
        current_yy = datetime.now().year % 100
        full_year = 2000 + yy if yy <= current_yy else 1900 + yy
        parsed["date_of_birth"] = f"{dd:02d}/{mm:02d}/{full_year}"
    except Exception:
        parsed["date_of_birth"] = dob_raw

    try:
        # Expiry: YYMMDD
        yy = int(expiry_raw[0:2])
        mm = int(expiry_raw[2:4])
        dd = int(expiry_raw[4:6])
        full_year = 2000 + yy
        parsed["date_of_expiry"] = f"{dd:02d}/{mm:02d}/{full_year}"
    except Exception:
        parsed["date_of_expiry"] = expiry_raw

    checksum_results = {
        "document_number": {
            "expected": doc_num_check,
            "calculated": calculate_check_digit(doc_num_raw),
            "valid": doc_num_valid,
        },
        "date_of_birth": {
            "expected": dob_check,
            "calculated": calculate_check_digit(dob_raw),
            "valid": dob_valid,
        },
        "date_of_expiry": {
            "expected": expiry_check,
            "calculated": calculate_check_digit(expiry_raw),
            "valid": expiry_valid,
        },
        "composite": {
            "expected": composite_check,
            "calculated": calculate_check_digit(comp_data),
            "valid": composite_valid,
        },
    }

    parsed["checksums"] = checksum_results
    parsed["mrz_valid"] = doc_num_valid and dob_valid and expiry_valid

    return parsed


# ============================================================
# FALLBACK VISUAL INSPECTION ZONE (VIZ) PARSERS
# ============================================================

def parse_viz_dates(raw_text: str) -> tuple:
    """Extracts Date of Birth and Expiry Date from Visual Inspection Zone."""
    dob = None
    expiry = None
    text_upper = raw_text.upper()

    dob_match = re.search(
        r"(?:DATE\s*OF\s*BIRTH|DOB|BIRTH)\s*[:\-]?\s*(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4})",
        text_upper,
    )
    if dob_match:
        dob = dob_match.group(1).replace(".", "/")

    exp_match = re.search(
        r"(?:DATE\s*OF\s*EXPIRY|EXPIRY|EXPIRATION|VALID\s*UNTIL)\s*[:\-]?\s*(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4})",
        text_upper,
    )
    if exp_match:
        expiry = exp_match.group(1).replace(".", "/")

    return dob, expiry


def parse_viz_name(raw_text: str) -> str:
    """Attempts to extract cardholder name from text lines."""
    text_upper = raw_text.upper()

    # Search for labeled Name field
    match = re.search(
        r"(?:NAME|SURNAME|GIVEN\s*NAME)\s*[:\-]?\s*([A-Z][A-Z\s]{2,40})",
        text_upper,
    )
    if match:
        candidate = match.group(1).strip()
        candidate = re.split(r"\b(?:DATE|DOB|SEX|NATIONALITY|PASSPORT|ADDRESS|PLACE)\b", candidate)[0].strip()
        if len(candidate) >= 3:
            return candidate

    return None


def parse_viz_document_number(raw_text: str) -> str:
    """Extracts passport or national document number from text."""
    text_upper = raw_text.upper()

    patterns = [
        r"PASSPORT\s*(?:NO|NUMBER|NUM|N)?\s*[:\-]?\s*([A-Z0-9]{6,12})",
        r"\b([A-Z][0-9]\s*[0-9]{6,8})\b",
        r"\b([A-Z][0-9]{7,8})\b",
    ]

    for p in patterns:
        m = re.search(p, text_upper)
        if m:
            return m.group(1).replace(" ", "")

    return None


# ============================================================
# MASTER EXTRACTION PIPELINE
# ============================================================

def extract_document_data(image_path: str) -> dict:
    """
    Main extraction interface for AEGISTID.
    Extracts raw OCR text, detects MRZ, computes ICAO 9303 checksums,
    and cross-correlates MRZ fields with the Visual Inspection Zone (VIZ).
    """
    raw_text = extract_full_text(image_path)
    mrz_lines = extract_mrz_lines(raw_text)

    # Initialize results dictionary
    data = {
        "raw_text": raw_text,
        "mrz": mrz_lines,
        "passport": False,
        "document_type": "Unknown Document",
        "passport_number": None,
        "document_number": None,
        "nationality": None,
        "name": None,
        "surname": None,
        "given_names": None,
        "date_of_birth": None,
        "date_of_expiry": None,
        "sex": None,
        "mrz_parsed": None,
        "mrz_valid": None,
        "checksums": {},
    }

    # If MRZ lines are found (TD3 Passport format: 2 lines)
    if len(mrz_lines) >= 2 and len(mrz_lines[-2]) >= 38 and len(mrz_lines[-1]) >= 38:
        try:
            mrz_info = parse_td3_mrz(mrz_lines[-2], mrz_lines[-1])
            data["mrz_parsed"] = mrz_info
            data["passport"] = (mrz_info["doc_type"] == "Passport")
            data["document_type"] = mrz_info["doc_type"]
            data["document_number"] = mrz_info["document_number"]
            data["passport_number"] = mrz_info["document_number"]
            data["nationality"] = mrz_info["nationality"]
            data["name"] = mrz_info["full_name"]
            data["surname"] = mrz_info["surname"]
            data["given_names"] = mrz_info["given_names"]
            data["date_of_birth"] = mrz_info["date_of_birth"]
            data["date_of_expiry"] = mrz_info["date_of_expiry"]
            data["sex"] = mrz_info["sex"]
            data["mrz_valid"] = mrz_info["mrz_valid"]
            data["checksums"] = mrz_info["checksums"]
        except Exception as exc:
            print(f"[AEGISTID MRZ] TD3 MRZ parse failed: {exc}")

    # Fallback to Visual Inspection Zone (VIZ) for any missing fields
    text_upper = raw_text.upper()
    if not data["passport"]:
        if "PASSPORT" in text_upper or "REPUBLIC OF INDIA" in text_upper:
            data["passport"] = True
            data["document_type"] = "Passport"

    if not data["passport_number"]:
        viz_num = parse_viz_document_number(raw_text)
        data["passport_number"] = viz_num
        data["document_number"] = viz_num

    if not data["nationality"]:
        if "INDIA" in text_upper or "INDIAN" in text_upper or "IND" in text_upper:
            data["nationality"] = "INDIAN"

    if not data["name"]:
        data["name"] = parse_viz_name(raw_text)

    viz_dob, viz_exp = parse_viz_dates(raw_text)
    if not data["date_of_birth"] and viz_dob:
        data["date_of_birth"] = viz_dob

    if not data["date_of_expiry"] and viz_exp:
        data["date_of_expiry"] = viz_exp

    if not data["sex"]:
        if re.search(r"\b(?:SEX|GENDER)\s*[:\-]?\s*M(?:ALE)?\b", text_upper):
            data["sex"] = "Male"
        elif re.search(r"\b(?:SEX|GENDER)\s*[:\-]?\s*F(?:EMALE)?\b", text_upper):
            data["sex"] = "Female"

    print(f"[AEGISTID OCR] Extraction complete. Doc: {data['document_type']}, Name: {data['name']}, Num: {data['document_number']}, MRZ Valid: {data['mrz_valid']}")
    return data