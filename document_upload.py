"""
AEGISTID - Document Upload Module
Handles secure file uploading, stream validation, magic-byte inspection,
multi-format image decoding, and automatic PDF-to-image rendering.
"""

import io
import os
import uuid
from pathlib import Path
from PIL import Image, UnidentifiedImageError
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR / "uploads"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp", "pdf"}


def allowed_file(filename):
    """Check if the filename has an allowed extension."""
    if not filename or "." not in filename:
        return False
    return filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def detect_file_signature(data: bytes) -> str:
    """
    Inspect magic bytes to determine actual file format regardless of extension.
    """
    if len(data) < 4:
        return "empty_or_too_small"

    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"%PDF"):
        return "pdf"
    if data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP":
        return "webp"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "gif"
    if data.startswith(b"BM"):
        return "bmp"

    return "unknown"


def convert_pdf_page_to_image(pdf_bytes: bytes, dpi: int = 250) -> Image.Image:
    """
    Render page 1 of a PDF document to a PIL Image using PyMuPDF.
    """
    try:
        import pymupdf
    except ImportError:
        try:
            import fitz as pymupdf
        except ImportError as exc:
            raise ValueError(
                "PDF uploaded but PyMuPDF is not installed. Please install pymupdf."
            ) from exc

    doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    if len(doc) == 0:
        raise ValueError("The uploaded PDF has no pages.")

    page = doc[0]
    # Render at high resolution for OCR and tamper analysis
    pix = page.get_pixmap(dpi=dpi)
    img_data = pix.tobytes("png")
    doc.close()

    image = Image.open(io.BytesIO(img_data)).convert("RGB")
    return image


def save_document(file_obj, destination_folder=None):
    """
    Securely reads uploaded bytes from a Flask FileStorage or file-like object,
    validates the true file signature, normalizes it to a high-quality RGB/PNG image,
    and saves it with a collision-resistant unique filename.

    Returns:
        str: Absolute file path to the saved image file.
    """
    if file_obj is None:
        raise ValueError("No file provided for upload.")

    filename = getattr(file_obj, "filename", None) or "document.jpg"

    # Reset stream pointer if possible
    if hasattr(file_obj, "seek"):
        try:
            file_obj.seek(0)
        except Exception:
            pass
    elif hasattr(file_obj, "stream") and hasattr(file_obj.stream, "seek"):
        try:
            file_obj.stream.seek(0)
        except Exception:
            pass

    # Read uploaded bytes
    if hasattr(file_obj, "read"):
        raw_bytes = file_obj.read()
    else:
        raw_bytes = bytes(file_obj)

    # Rewind stream again so caller can reuse if needed
    if hasattr(file_obj, "seek"):
        try:
            file_obj.seek(0)
        except Exception:
            pass

    if not raw_bytes or len(raw_bytes) < 16:
        raise ValueError("The uploaded file is empty or corrupted (under 16 bytes).")

    target_dir = Path(destination_folder) if destination_folder else UPLOAD_FOLDER
    target_dir.mkdir(parents=True, exist_ok=True)

    sig = detect_file_signature(raw_bytes)
    print(f"[AEGISTID Upload] Filename: {filename}, Size: {len(raw_bytes)} bytes, Magic Type: {sig}")

    safe_stem = secure_filename(Path(filename).stem)
    if not safe_stem:
        safe_stem = "document"

    unique_id = uuid.uuid4().hex

    # Handle PDF masquerading or native PDF upload
    if sig == "pdf":
        print("[AEGISTID Upload] PDF document detected. Rendering first page to high-res image...")
        try:
            image = convert_pdf_page_to_image(raw_bytes, dpi=250)
            output_filename = f"{unique_id}_{safe_stem}_page1.png"
            output_path = target_dir / output_filename
            image.save(output_path, format="PNG")
            print(f"[AEGISTID Upload] PDF page rendered successfully: {output_path}")
            return str(output_path.resolve())
        except Exception as exc:
            raise ValueError(f"Failed to render uploaded PDF document: {exc}") from exc

    # Handle images
    try:
        # Load and verify with Pillow
        image = Image.open(io.BytesIO(raw_bytes))
        image.load()  # Force full decoding of image data

        # Normalize format: convert RGBA/CMYK/Palette to clean RGB
        if image.mode in ("RGBA", "LA", "P"):
            output_image = image.convert("RGB")
            extension = ".png"
            save_format = "PNG"
            save_kwargs = {}
        else:
            output_image = image.convert("RGB")
            extension = ".jpg"
            save_format = "JPEG"
            save_kwargs = {"quality": 95, "subsampling": 0}

        output_filename = f"{unique_id}_{safe_stem}{extension}"
        output_path = target_dir / output_filename
        output_image.save(output_path, format=save_format, **save_kwargs)

        print(f"[AEGISTID Upload] Decoded {image.format} image ({image.size[0]}x{image.size[1]} {image.mode}) -> Saved {output_path.name}")
        return str(output_path.resolve())

    except (UnidentifiedImageError, OSError, SyntaxError) as exc:
        # If Pillow fails, check if PyMuPDF or OpenCV can decode it
        print(f"[AEGISTID Upload] Pillow decode failed: {exc}. Attempting PyMuPDF/OpenCV fallback...")
        try:
            import cv2
            import numpy as np

            arr = np.frombuffer(raw_bytes, dtype=np.uint8)
            cv_img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            if cv_img is not None and cv_img.size > 0:
                output_filename = f"{unique_id}_{safe_stem}.jpg"
                output_path = target_dir / output_filename
                cv2.imwrite(str(output_path), cv_img, [cv2.IMWRITE_JPEG_QUALITY, 95])
                print(f"[AEGISTID Upload] OpenCV fallback decoded image -> Saved {output_path.name}")
                return str(output_path.resolve())
        except Exception:
            pass

        raise ValueError(
            f"Unable to decode uploaded image. The file format is not a recognized or valid image (Detected signature: {sig}). "
            "Please ensure the file is a valid JPG, PNG, or PDF document."
        ) from exc
