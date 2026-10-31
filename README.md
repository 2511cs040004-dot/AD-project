# AEGISTID — AI-Powered Identity Document Authentication & Fraud Detection System

**AEGISTID** is an enterprise-grade forensic document authentication and anti-fraud screening platform. It ingests identity credentials (passports, national ID cards, driving licenses, and PDF scans), extracts machine-readable data, inspects image compression and edge noise anomalies, detects facial portraits, validates chronological and ICAO Doc 9303 checksums, generates SHA-256 cryptographic hashes, and computes a multi-factorial security risk assessment.

---

## 🛡️ Key Features

1. **User Authentication & Role-Based Access Control**:
   - Secure analyst sign-up, sign-in, and session management.
   - Salted password hashing via PBKDF2/scrypt (`werkzeug.security`).
   - One-click **Demo Mode** for instant examiner testing (`analyst` / `Password@123`).
2. **Robust Multi-Format Intake**:
   - Accepts JPG, JPEG, PNG, WEBP, and PDF documents up to 10 MB.
   - **Stream Rewinding & Magic-Byte Detection**: Inspects file signatures directly, completely preventing `Pillow cannot identify image file` errors.
   - **Automatic High-Res PDF Rendering**: Native PyMuPDF integration renders PDF credentials at 250 DPI for seamless forensic processing.
3. **Image Preprocessing Engine**:
   - Multi-orientation detection (0°, 90°, 180°, 270°) using OCR token heuristics.
   - LAB color-space CLAHE (Contrast Limited Adaptive Histogram Equalization) and unsharp masking to enhance text contrast while preserving natural face and ink tones.
4. **OCR & ICAO Doc 9303 MRZ Engine**:
   - Multi-threshold OCR extraction (Grayscale, CLAHE, Otsu, Adaptive Gaussian).
   - Machine-Readable Zone (MRZ) parser for 2-line TD3 passports and 3-line TD1/TD2 cards.
   - **ICAO 7-3-1 Weighting Checksum Engine**: Validates Document Number, Date of Birth, Expiry Date, and Composite check digits.
5. **Multi-Spectral Tampering & ELA Screening**:
   - Error Level Analysis (ELA) identifies localized compression disparities.
   - Laplacian edge variance detects copy-paste inserts and altered text overlays.
   - Unique timestamped visualization maps saved for human audit.
6. **Facial Portrait Detection**:
   - OpenCV YuNet Deep Neural Network (DNN) face detection with Haar Cascade fallback.
   - Identifies candidate photo on credential without making false biometric 1:1 claims.
7. **Signature Analysis**:
   - 1-to-1 comparative verification when a reference specimen signature is uploaded.
   - Automatic signature zone localization and extraction when no reference is provided.
8. **Forensic Metadata Inspection**:
   - Detailed EXIF header parsing, camera tags, dimensions, color modes, and DPI.
   - Detects digital manipulation signatures (Photoshop, GIMP, Canva, Corel, Paint.NET, Photopea).
9. **Cryptographic SHA-256 Sealing**:
   - Bit-level chunked hashing for immutable document tracking.
10. **Multi-Factorial Risk Assessment Engine**:
    - Weighted scoring (0–100) combining validation status, MRZ check digits, ELA tampering, face presence, expiry status, and metadata.
    - Transparent classification: **LOW RISK** (<30), **SUSPICIOUS** (30–59), and **HIGH RISK** (≥60).
    - Clear isolation of inconclusive tests from failed checks.
11. **Official Verification Reports & PDF Export**:
    - Interactive executive report with visual evidence gallery.
    - Print / Save as PDF mode (`@media print`) for official audit certificates.
12. **Audit History & Searchable Logs**:
    - Filterable history log by filename, SHA-256 hash, or risk status.
    - Full record preview and secure deletion.

---

## 📁 Project Architecture

```
project/
├── app.py                      # Core Flask web server, auth, routing, and pipeline orchestration
├── document_upload.py          # Secure upload handler, magic-byte inspection & PDF renderer
├── preprocessing.py            # Image orientation, LAB CLAHE, and scaling pipeline
├── ocr_mrz.py                  # OCR extraction, MRZ parsing & ICAO 9303 checksum validation
├── validation.py               # Document logic validation, age & expiry checks
├── tamper_detection.py         # Error Level Analysis (ELA) & edge noise variance
├── face_verification.py        # YuNet DNN & Haar Cascade face detection
├── face_detection_yunet_2023mar.onnx # Pre-trained ONNX face model
├── signature_verification.py   # Signature 1-to-1 comparison & in-document crop
├── metadata_analysis.py        # EXIF analysis & image editing software detection
├── hashing.py                  # Chunked SHA-256 cryptographic hashing
├── risk_engine.py              # Multi-factorial weighted risk engine
├── requirements.txt            # Python dependencies
├── README.md                   # System documentation
├── verification_history.db     # SQLite database for users and verification records
├── templates/
│   ├── index.html              # Landing page with fast intake panel
│   ├── dashboard.html          # Operations center dashboard & metrics
│   ├── login.html              # Accessible login with 1-click Demo mode
│   ├── register.html           # Examiner registration
│   ├── result.html             # Executive forensic verification report & print export
│   ├── history.html            # Searchable audit history log
│   └── document_preview.html   # High-resolution credential inspector
├── static/
│   └── style.css               # Cybersecurity dark theme, glassmorphism, responsive styles
├── uploads/                    # Secure storage for original ingested documents
└── processed/                  # Preprocessed images, ELA heatmaps, and face crops
```

---

## 🛠️ Installation & Setup (Windows)

### 1. Prerequisites
- **Python**: 3.10+ (tested on Python 3.14)
- **Tesseract OCR**:
  - Install Tesseract OCR from [UB-Mannheim/tesseract](https://github.com/UB-Mannheim/tesseract/wiki) to `C:\Program Files\Tesseract-OCR\tesseract.exe`.
  - The application automatically discovers standard Tesseract installation paths.

### 2. Install Python Dependencies
Open PowerShell or Command Prompt in the project folder and run:
```powershell
pip install -r requirements.txt
```

### 3. Start Application
```powershell
python app.py
```

Open your browser at:
```
http://127.0.0.1:5000
```

---

## 🔑 Default Credentials

AEGISTID comes pre-configured with a default Senior Security Analyst account:
- **Username**: `analyst`
- **Password**: `Password@123`
- **1-Click Instant Demo Access**: On the login page, simply click **"⚡ 1-Click Demo Sign-in"** to access the operations console immediately without entering credentials.

---

## 🔍 Investigation of the Pillow Decoding Error

### Root Cause
The error `Pillow could not decode the uploaded image: cannot identify image file` occurred because:
1. **Masquerading / Misnamed Files**: Files with names ending in `.JPG` (such as `passport.JPG`) were actually **PDF documents** (magic bytes `%PDF-1.4`).
2. **Lack of File Signature Inspection**: The system previously relied on string extension checks (`.rsplit('.', 1)[1]`). When Pillow tried to open the PDF bytes as an image, it threw `UnidentifiedImageError: cannot identify image file`.
3. **Stream Position**: Reading un-rewound Flask `FileStorage` streams without `seek(0)` could result in empty or partial byte buffers.

### Solution Applied
- Implemented `detect_file_signature()` in `document_upload.py` to inspect raw magic bytes before passing them to any decoder.
- Integrated `pymupdf` to automatically detect PDF files and render the credential page to a crisp 250 DPI RGB image.
- Enforced stream rewinding (`seek(0)`) before and after byte reading.
- Added graceful fallbacks to OpenCV `imdecode` if standard Pillow decoding encounters edge-case formats.

---

## ⚖️ Forensic Disclaimer
AEGISTID provides automated heuristic screening assistance for identity document verification. Cryptographic hashes confirm file integrity during intake. Face detection confirms portrait presence on the credential, not live biological 1:1 identity. The automated risk score assists human examiners and must not be interpreted as an empirical probability of criminal fraud.
