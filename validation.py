"""
AEGISTID - Document Validation Module
Validates extracted credential fields, chronological date relationships,
ICAO 9303 MRZ checksum integrity, and cross-zone consistency.
"""

from datetime import datetime, date
import re


def parse_date_flexibly(date_str: str):
    """Parses various date formats into a datetime.date object."""
    if not date_str or not isinstance(date_str, str):
        return None

    date_str = date_str.strip().replace(".", "/").replace("-", "/")
    formats = [
        "%d/%m/%Y",
        "%d/%m/%y",
        "%Y/%m/%d",
        "%m/%d/%Y",
        "%m/%d/%y",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt).date()
        except ValueError:
            continue

    return None


def validate_document(document_data: dict) -> dict:
    """
    Evaluates extracted document data against international credential rules.

    Args:
        document_data (dict): Output from extract_document_data()

    Returns:
        dict: Structured validation verdict, individual checks, date audit,
              MRZ checksum status, warnings, and errors.
    """
    if not isinstance(document_data, dict):
        return {
            "valid": False,
            "status": "Invalid",
            "message": "Invalid document data received for validation.",
            "checks": {},
            "warnings": ["No readable document structure"],
            "errors": ["Extraction failed"],
        }

    passport_detected = bool(document_data.get("passport", False))
    doc_type = document_data.get("document_type", "Unknown Document")
    nationality = document_data.get("nationality")
    doc_number = document_data.get("document_number") or document_data.get("passport_number")
    name = document_data.get("name")
    dob_str = document_data.get("date_of_birth")
    exp_str = document_data.get("date_of_expiry")
    mrz_valid = document_data.get("mrz_valid")
    checksums = document_data.get("checksums", {})

    checks = {}
    warnings = []
    errors = []
    today = date.today()

    # 1. Document Recognition Check
    checks["document_identified"] = bool(passport_detected or doc_type != "Unknown Document")
    if not checks["document_identified"]:
        errors.append("Document type could not be confidently identified.")

    # 2. Document Number Check
    checks["document_number_present"] = bool(doc_number and len(doc_number) >= 5)
    if not checks["document_number_present"]:
        errors.append("Document / Passport number is missing or illegible.")

    # 3. Name Field Check
    checks["name_present"] = bool(name and len(name.strip()) >= 3)
    if not checks["name_present"]:
        errors.append("Holder name is missing or illegible.")

    # 4. Nationality Check
    checks["nationality_present"] = bool(nationality)
    if not checks["nationality_present"]:
        warnings.append("Issuing country or nationality could not be resolved.")

    # 5. Date of Birth Logic Check
    checks["dob_valid"] = False
    dob_date = parse_date_flexibly(dob_str)
    age = None

    if dob_date:
        if dob_date > today:
            errors.append(f"Date of birth ({dob_str}) is in the future.")
        else:
            age = (today - dob_date).days // 365
            if age > 115:
                warnings.append(f"Calculated age ({age} years) is unusually high.")
            checks["dob_valid"] = True
    else:
        if dob_str:
            warnings.append(f"Date of birth '{dob_str}' could not be parsed into a standard calendar date.")
        else:
            warnings.append("Date of birth is not visible on the document.")

    # 6. Expiry Date & Credential Validity Check
    checks["expiry_valid"] = False
    checks["document_not_expired"] = None
    exp_date = parse_date_flexibly(exp_str)
    days_to_expiry = None
    expiry_status = "Unknown"

    if exp_date:
        checks["expiry_valid"] = True
        days_to_expiry = (exp_date - today).days

        if days_to_expiry < 0:
            checks["document_not_expired"] = False
            expiry_status = "Expired"
            warnings.append(f"Credential has expired ({abs(days_to_expiry)} days ago on {exp_str}).")
        elif days_to_expiry < 180:
            checks["document_not_expired"] = True
            expiry_status = "Expiring Soon (<6 Months)"
            warnings.append(f"Credential expires soon (in {days_to_expiry} days on {exp_str}).")
        else:
            checks["document_not_expired"] = True
            expiry_status = "Valid"
    else:
        if exp_str:
            warnings.append(f"Expiry date '{exp_str}' could not be standardized.")

    # 7. Date Sequence Consistency Check (DOB must precede Expiry)
    if dob_date and exp_date:
        if dob_date >= exp_date:
            errors.append("Chronological error: Date of birth occurs on or after expiration date.")

    # 8. ICAO MRZ Checksum Validation
    checks["mrz_checksums_passed"] = None
    if mrz_valid is not None:
        checks["mrz_checksums_passed"] = bool(mrz_valid)
        if not mrz_valid:
            failed_ck = [k for k, v in checksums.items() if not v.get("valid", False)]
            errors.append(f"MRZ checksum mismatch detected in field(s): {', '.join(failed_ck) if failed_ck else 'Check digits'}")

    # Summary Assessment
    total_checks = len(checks)
    passed_checks = sum(1 for v in checks.values() if v is True)

    critical_passed = (
        checks.get("document_identified")
        and checks.get("document_number_present")
        and checks.get("name_present")
        and len(errors) == 0
    )

    if critical_passed and checks.get("document_not_expired") is not False:
        status = "Valid"
        valid = True
        message = "Document successfully validated against credential format and date rules."
    elif checks.get("document_identified") and (checks.get("document_number_present") or checks.get("name_present")):
        status = "Partially Valid"
        valid = (len(errors) == 0)
        message = "Document recognized, but some fields or checksums require review."
    else:
        status = "Invalid"
        valid = False
        message = "Document validation failed. Essential security or identity fields are missing."

    return {
        "valid": valid,
        "status": status,
        "message": message,
        "checks": checks,
        "passed": passed_checks,
        "total": total_checks,
        "warnings": warnings,
        "errors": errors,
        "date_analysis": {
            "dob": dob_str,
            "calculated_age": age,
            "expiry_date": exp_str,
            "expiry_status": expiry_status,
            "days_to_expiry": days_to_expiry,
        },
        "mrz_status": {
            "mrz_detected": bool(document_data.get("mrz")),
            "mrz_valid": mrz_valid,
            "checksums": checksums,
        },
    }