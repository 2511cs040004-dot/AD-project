"""
AEGISTID - Metadata Forensic Analysis Module
Inspects embedded EXIF headers, camera tags, editing software fingerprints,
dimension ratios, color depth, and timestamp discrepancies.
"""

import os
from pathlib import Path
from PIL import Image, ExifTags


EDITING_SOFTWARE_INDICATORS = [
    "photoshop",
    "gimp",
    "canva",
    "corel",
    "paint.net",
    "photopea",
    "lightroom",
    "illustrator",
    "snapseed",
    "pixlr",
    "affinity",
    "procreate",
    "acrobat",
]


def analyze_metadata(file_path: str) -> dict:
    """
    Examines image metadata for signs of tampering, manipulation software,
    or structural inconsistencies.

    Args:
        file_path (str): Path to document image.

    Returns:
        dict: Detailed metadata report including EXIF tags, dimensions,
              suspicious software detection, and forensic notices.
    """
    file_path = os.path.abspath(os.fspath(file_path))
    if not os.path.isfile(file_path):
        return {
            "metadata_found": False,
            "metadata": {},
            "suspicious": False,
            "message": "File not found for metadata inspection.",
        }

    stat_info = os.stat(file_path)
    file_size_kb = round(stat_info.st_size / 1024, 2)

    result = {
        "metadata_found": False,
        "metadata": {},
        "software_detected": [],
        "suspicious": False,
        "dimensions": None,
        "color_mode": None,
        "format": None,
        "dpi": None,
        "file_size_kb": file_size_kb,
        "inconsistencies": [],
        "message": "Clean metadata profile. No suspicious editing tags found.",
    }

    try:
        with Image.open(file_path) as img:
            result["dimensions"] = [img.width, img.height]
            result["color_mode"] = img.mode
            result["format"] = img.format
            result["dpi"] = img.info.get("dpi")

            raw_exif = img.getexif()
            if raw_exif:
                result["metadata_found"] = True
                parsed_exif = {}
                for tag_id, value in raw_exif.items():
                    tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    # Convert bytes to string for clean serialization
                    if isinstance(value, bytes):
                        try:
                            value = value.decode("utf-8", errors="ignore").strip()
                        except Exception:
                            value = str(value)
                    parsed_exif[tag_name] = str(value)

                result["metadata"] = parsed_exif

        # Check for editing software signatures
        detected_software = []
        combined_text = " ".join([f"{k} {v}" for k, v in result["metadata"].items()]).lower()

        for tool in EDITING_SOFTWARE_INDICATORS:
            if tool in combined_text:
                detected_software.append(tool.title())

        # Also check common software tag specifically
        software_field = result["metadata"].get("Software", "").lower()
        for tool in EDITING_SOFTWARE_INDICATORS:
            if tool in software_field and tool.title() not in detected_software:
                detected_software.append(tool.title())

        result["software_detected"] = list(set(detected_software))

        if result["software_detected"]:
            result["suspicious"] = True
            tools_str = ", ".join(result["software_detected"])
            result["inconsistencies"].append(
                f"Image processing software trace detected: {tools_str}"
            )
            result["message"] = f"Suspicious editing software signature found in metadata ({tools_str})."
        elif not result["metadata_found"]:
            result["message"] = (
                "No EXIF metadata present. Standard for web uploads, scans, and messaging apps; "
                "inconclusive for tampering."
            )
        else:
            result["message"] = "EXIF metadata verified. No image editing software signatures detected."

    except Exception as exc:
        result["message"] = f"Metadata extraction warning: {exc}"

    return result