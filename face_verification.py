"""
AEGISTID - Face Detection Module
Locates and validates the presence of an identity portrait on documents
using OpenCV YuNet DNN with Haar Cascade fallback.
"""

import os
import uuid
from pathlib import Path
import cv2

BASE_DIR = Path(__file__).resolve().parent
PROCESSED_DIR = BASE_DIR / "processed"
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH = BASE_DIR / "face_detection_yunet_2023mar.onnx"


def detect_with_yunet(image):
    """Executes YuNet deep neural network face detector."""
    if not MODEL_PATH.is_file():
        return []

    height, width = image.shape[:2]
    detector = cv2.FaceDetectorYN.create(
        str(MODEL_PATH),
        "",
        (width, height),
        0.65,  # Score threshold
        0.3,   # NMS threshold
        5000,
    )
    detector.setInputSize((width, height))
    _, faces = detector.detect(image)
    if faces is None:
        return []
    return faces


def detect_with_haar(image):
    """Fallback detector using OpenCV pre-trained Haar Cascades."""
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
    if not os.path.isfile(cascade_path):
        return []

    cascade = cv2.CascadeClassifier(cascade_path)
    faces = cascade.detectMultiScale(
        gray,
        scaleFactor=1.1,
        minNeighbors=4,
        minSize=(40, 40),
    )
    results = []
    for (x, y, w, h) in faces:
        results.append([x, y, w, h, 0.80])
    return results


def detect_faces(image_path: str) -> dict:
    """
    Detects faces on the credential image and annotates the candidate portrait.

    Args:
        image_path (str): Path to document image.

    Returns:
        dict: Facial detection status, bounding box, visual path, and legal disclaimer.
    """
    image_path = os.path.abspath(os.fspath(image_path))
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Image for face detection not found: {image_path}")

    image = cv2.imread(image_path)
    if image is None:
        raise ValueError("OpenCV unable to decode document for face detection.")

    orig_h, orig_w = image.shape[:2]

    # Run detection (YuNet with Haar fallback)
    raw_faces = []
    detector_used = "YuNet DNN"
    try:
        raw_faces = detect_with_yunet(image)
    except Exception as exc:
        print(f"[AEGISTID Face] YuNet error: {exc}. Falling back to Haar Cascade...")

    if len(raw_faces) == 0:
        raw_faces = detect_with_haar(image)
        detector_used = "Haar Cascade Fallback"

    # Filter out tiny noise detections
    valid_faces = []
    img_area = orig_h * orig_w

    for f in raw_faces:
        x, y, w, h = int(f[0]), int(f[1]), int(f[2]), int(f[3])
        face_area = w * h
        # Must be at least 35x35 and >= 0.25% of the total document area
        if w >= 35 and h >= 35 and (face_area / img_area) >= 0.0025:
            conf = float(f[4]) if len(f) > 4 else 0.85
            valid_faces.append({"bbox": (x, y, w, h), "conf": conf})

    # Pick primary portrait (largest bounding box)
    selected_face = None
    if valid_faces:
        selected_face = max(valid_faces, key=lambda item: item["bbox"][2] * item["bbox"][3])

    # Generate annotated image
    result_image = image.copy()
    unique_id = uuid.uuid4().hex
    face_filename = f"face_{unique_id}.jpg"
    output_path = PROCESSED_DIR / face_filename

    if selected_face:
        x, y, w, h = selected_face["bbox"]
        # Draw tech-cyan corner box
        cv2.rectangle(result_image, (x, y), (x + w, y + h), (0, 240, 255), 3)

        # Label background
        label = "CREDENTIAL PORTRAIT"
        (lw, lh), _ = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, 0.6, 2)
        cv2.rectangle(result_image, (x, max(0, y - lh - 12)), (x + lw + 10, max(lh + 12, y)), (0, 20, 40), -1)
        cv2.putText(
            result_image,
            label,
            (x + 5, max(lh + 2, y - 6)),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.55,
            (0, 240, 255),
            2,
        )

    cv2.imwrite(str(output_path), result_image, [cv2.IMWRITE_JPEG_QUALITY, 95])

    detected = selected_face is not None
    face_count = len(valid_faces)

    if detected:
        message = f"Valid document portrait located ({face_count} face candidate{'s' if face_count > 1 else ''} evaluated via {detector_used})."
    else:
        message = "No human portrait detected on document image."

    return {
        "verified": detected,
        "faces_detected": face_count,
        "count": face_count,
        "confidence": round(selected_face["conf"], 2) if selected_face else 0.0,
        "bbox": list(selected_face["bbox"]) if selected_face else None,
        "message": message,
        "detector": detector_used,
        "face_image": face_filename,
        "face_path": str(output_path.resolve()),
        "disclaimer": "Verifies presence of credential photograph only. Does not perform live biometric 1:1 or 1:N identity verification.",
    }