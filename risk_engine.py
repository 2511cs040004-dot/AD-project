"""
AEGISTID - Risk Assessment Engine
Calculates a documented, multi-factorial risk score (0-100) using configurable
heuristic rules, itemizes risk contributing factors, positive authentic indicators,
and clearly isolates inconclusive tests from failed security checks.
"""


def calculate_risk(
    validation_result: dict,
    tamper_result: dict,
    face_result: dict,
    signature_result: dict,
    metadata_result: dict,
    hash_result: str = None,
) -> dict:
    """
    Computes a composite security risk assessment for the document credential.

    Args:
        validation_result (dict): Output from validate_document()
        tamper_result (dict): Output from detect_tampering()
        face_result (dict): Output from detect_faces()
        signature_result (dict): Output from verify_signature()
        metadata_result (dict): Output from analyze_metadata()
        hash_result (str, optional): SHA-256 digest of original upload.

    Returns:
        dict: Final risk score (0-100), classification status, itemized reasons,
              positive indicators, inconclusive checks, and legal disclaimer.
    """
    risk_score = 0
    reasons = []
    positive_indicators = []
    inconclusive_checks = []
    rules_applied = []

    # Safe access helpers
    validation = validation_result if isinstance(validation_result, dict) else {}
    tamper = tamper_result if isinstance(tamper_result, dict) else {}
    face = face_result if isinstance(face_result, dict) else {}
    signature = signature_result if isinstance(signature_result, dict) else {}
    metadata = metadata_result if isinstance(metadata_result, dict) else {}

    # -------------------------------------------------------------
    # 1. DOCUMENT IDENTIFICATION & VALIDATION (Max: 30 pts)
    # -------------------------------------------------------------
    val_status = str(validation.get("status", "")).lower()
    is_valid = validation.get("valid", False) or val_status in ("valid", "passed")

    if not is_valid:
        if val_status == "partially valid":
            pts = 15
            risk_score += pts
            reasons.append("Document validation partially failed: Some key identity fields or checksums are missing.")
            rules_applied.append({"factor": "Partial Document Validation", "weight": pts})
        else:
            pts = 30
            risk_score += pts
            reasons.append("Core document validation failed: Critical identity fields or structure are unverified.")
            rules_applied.append({"factor": "Core Validation Failure", "weight": pts})
    else:
        positive_indicators.append("Core identity fields (Name, Number, Dates) successfully validated.")

    # -------------------------------------------------------------
    # 2. ICAO 9303 MRZ CHECKSUMS (Max: 25 pts)
    # -------------------------------------------------------------
    mrz_status = validation.get("mrz_status", {})
    mrz_detected = mrz_status.get("mrz_detected", False)
    mrz_valid = mrz_status.get("mrz_valid")

    if mrz_detected:
        if mrz_valid is False:
            pts = 25
            risk_score += pts
            reasons.append("Critical: ICAO Doc 9303 MRZ mathematical checksum verification failed.")
            rules_applied.append({"factor": "MRZ Checksum Mismatch", "weight": pts})
        elif mrz_valid is True:
            positive_indicators.append("ICAO Doc 9303 MRZ 7-3-1 check digit integrity verified.")
    else:
        inconclusive_checks.append("Document does not contain an ICAO MRZ zone (common on regional IDs/licenses).")

    # -------------------------------------------------------------
    # 3. EXPIRATION DATE AUDIT (Max: 15 pts)
    # -------------------------------------------------------------
    date_analysis = validation.get("date_analysis", {})
    expiry_status = date_analysis.get("expiry_status")

    if expiry_status == "Expired":
        pts = 15
        risk_score += pts
        reasons.append(f"Document credential has expired (Expired: {date_analysis.get('expiry_date')}).")
        rules_applied.append({"factor": "Credential Expired", "weight": pts})
    elif expiry_status == "Expiring Soon (<6 Months)":
        pts = 5
        risk_score += pts
        reasons.append(f"Document expires within 6 months ({date_analysis.get('expiry_date')}).")
        rules_applied.append({"factor": "Impending Expiry", "weight": pts})
    elif expiry_status == "Valid":
        positive_indicators.append(f"Document validity period active (Expires: {date_analysis.get('expiry_date')}).")

    # -------------------------------------------------------------
    # 4. DIGITAL TAMPERING & ELA SCREENING (Max: 25 pts)
    # -------------------------------------------------------------
    if tamper.get("tampered", False):
        pts = 25
        risk_score += pts
        reasons.append(tamper.get("message", "Error Level Analysis detected anomalous localized compression artifacts."))
        rules_applied.append({"factor": "Tamper/ELA Anomaly", "weight": pts})
    else:
        positive_indicators.append("Error Level Analysis (ELA) and edge noise profiles show no localized tampering.")

    # -------------------------------------------------------------
    # 5. FACIAL PORTRAIT DETECTION (Max: 15 pts)
    # -------------------------------------------------------------
    face_verified = face.get("verified", False)
    if not face_verified:
        pts = 15
        risk_score += pts
        reasons.append("No facial portrait located on credential (expected for travel passports and photo IDs).")
        rules_applied.append({"factor": "Missing Credential Portrait", "weight": pts})
    else:
        positive_indicators.append(f"Identity portrait confirmed on document ({face.get('faces_detected', 1)} face located).")

    # -------------------------------------------------------------
    # 6. SIGNATURE COMPARISON (Max: 20 pts)
    # -------------------------------------------------------------
    ref_provided = signature.get("reference_provided", False)
    if ref_provided:
        sig_verified = signature.get("verified", False)
        if not sig_verified:
            pts = 20
            risk_score += pts
            sim = signature.get("similarity", 0)
            reasons.append(f"1-to-1 Signature mismatch detected (Specimen match score: {sim}%).")
            rules_applied.append({"factor": "Signature Specimen Mismatch", "weight": pts})
        else:
            sim = signature.get("similarity", 100)
            positive_indicators.append(f"Signature verified against uploaded reference specimen ({sim}% match).")
    else:
        inconclusive_checks.append("Signature matching was inconclusive: No reference signature specimen was provided.")

    # -------------------------------------------------------------
    # 7. METADATA FORENSIC AUDIT (Max: 15 pts)
    # -------------------------------------------------------------
    if metadata.get("suspicious", False):
        pts = 15
        risk_score += pts
        tools = ", ".join(metadata.get("software_detected", [])) or "Editing software"
        reasons.append(f"Editing software signature ({tools}) discovered in image metadata.")
        rules_applied.append({"factor": "Suspicious Software Metadata", "weight": pts})
    else:
        if metadata.get("metadata_found", False):
            positive_indicators.append("Image metadata is consistent with native capture equipment.")
        else:
            inconclusive_checks.append("EXIF metadata stripped (typical for web submissions, messaging, or scanner exports).")

    # -------------------------------------------------------------
    # 8. CRYPTOGRAPHIC HASH (Max: 10 pts)
    # -------------------------------------------------------------
    if not hash_result:
        pts = 10
        risk_score += pts
        reasons.append("Cryptographic SHA-256 seal could not be computed.")
        rules_applied.append({"factor": "Missing Cryptographic Digest", "weight": pts})
    else:
        positive_indicators.append("Cryptographic SHA-256 integrity seal calculated and registered.")

    # Bound risk score between 0 and 100
    final_score = max(0, min(100, risk_score))

    # Determine risk category
    if final_score >= 60:
        status = "HIGH RISK"
        alert = "CRITICAL ALERT: Significant signs of fraud, tampering, or identity inconsistencies detected."
        badge_class = "danger"
    elif final_score >= 30:
        status = "SUSPICIOUS"
        alert = "WARNING: Suspicious indicators or missing mandatory verification criteria require manual review."
        badge_class = "warning"
    else:
        status = "LOW RISK"
        alert = "AUTHENTICITY CONFIDENCE STRONG: Document passed key automated screening checks."
        badge_class = "success"

    return {
        "risk_score": final_score,
        "status": status,
        "badge_class": badge_class,
        "alert": alert,
        "reasons": reasons,
        "positive_indicators": positive_indicators,
        "inconclusive_checks": inconclusive_checks,
        "rules_applied": rules_applied,
        "disclaimer": (
            "AEGISTID automated risk scoring represents heuristic screening indicators for decision support. "
            "It does not constitute absolute proof of fraud or legal certification of identity."
        ),
    }