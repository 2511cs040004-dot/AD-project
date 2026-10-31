"""
AEGISTID — AI-Powered Identity Document Authentication and Fraud Detection System
Complete Flask Web Application
"""

import os
import json
import uuid
import sqlite3
import hashlib
from functools import wraps
from datetime import datetime
from pathlib import Path

from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    send_from_directory,
    abort,
    flash,
    session,
    g,
    jsonify,
    make_response,
)
from werkzeug.security import generate_password_hash, check_password_hash

# Integrated Pipeline Modules
from document_upload import save_document, allowed_file
from preprocessing import preprocess_document
from ocr_mrz import extract_document_data
from validation import validate_document
from tamper_detection import detect_tampering
from face_verification import detect_faces
from signature_verification import verify_signature
from metadata_analysis import analyze_metadata
from hashing import calculate_sha256
from risk_engine import calculate_risk


# ==================================================
# APPLICATION CONFIGURATION
# ==================================================

app = Flask(__name__)
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "aegistid-cyber-sec-key-7f9a8b1c-2026-prod",
)

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR / "uploads"
PROCESSED_FOLDER = BASE_DIR / "processed"
DATABASE_PATH = BASE_DIR / "verification_history.db"

UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
PROCESSED_FOLDER.mkdir(parents=True, exist_ok=True)

app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["PROCESSED_FOLDER"] = str(PROCESSED_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB upload limit


# ==================================================
# DATABASE MANAGEMENT & SCHEMA INITIALIZATION
# ==================================================

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(str(DATABASE_PATH))
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def initialize_database():
    """Initializes tables and seeds default user if none exists."""
    with sqlite3.connect(str(DATABASE_PATH)) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT,
                role TEXT DEFAULT 'Senior Analyst',
                created_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS verification_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL,
                processed_filename TEXT,
                verified_at TEXT NOT NULL,
                status TEXT,
                risk_score REAL,
                sha256 TEXT,
                details_json TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

        # Migration check: ensure user_id column exists
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(verification_history)")
        columns = [col[1] for col in cur.fetchall()]
        if "user_id" not in columns:
            conn.execute("ALTER TABLE verification_history ADD COLUMN user_id INTEGER REFERENCES users(id);")

        # Seed default senior analyst user if table is empty
        cur.execute("SELECT id FROM users WHERE username = ?", ("analyst",))
        if not cur.fetchone():
            conn.execute("""
                INSERT INTO users (username, email, password_hash, full_name, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                "analyst",
                "analyst@aegistid.gov",
                generate_password_hash("Password@123"),
                "Chief Security Analyst",
                "Senior Forensic Examiner",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ))
            conn.commit()


initialize_database()


# ==================================================
# USER AUTHENTICATION & ACCESS CONTROL
# ==================================================

def get_current_user():
    """Returns the currently logged-in user dictionary or None."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


@app.context_processor
def inject_user():
    """Injects current_user into all Jinja2 templates."""
    return {"current_user": get_current_user()}


def login_required(view_func):
    """Decorator to enforce authenticated session."""
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if session.get("user_id") is None:
            flash("Please sign in to access this security workspace.")
            return redirect(url_for("login", next=request.url))
        return view_func(*args, **kwargs)
    return wrapped_view


# ==================================================
# DATABASE OPERATIONS
# ==================================================

def save_history_record(
    user_id,
    filename,
    stored_filename,
    processed_filename,
    status,
    risk_score,
    sha256_value,
    details,
):
    verified_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db = get_db()
    cursor = db.execute("""
        INSERT INTO verification_history (
            user_id,
            filename,
            stored_filename,
            processed_filename,
            verified_at,
            status,
            risk_score,
            sha256,
            details_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        filename,
        stored_filename,
        processed_filename,
        verified_at,
        str(status),
        float(risk_score) if isinstance(risk_score, (int, float)) else None,
        str(sha256_value) if sha256_value else None,
        json.dumps(details, default=str),
    ))
    db.commit()
    return cursor.lastrowid


def get_history_record(record_id, user_id=None):
    db = get_db()
    if user_id:
        return db.execute(
            "SELECT * FROM verification_history WHERE id = ? AND user_id = ?",
            (record_id, user_id),
        ).fetchone()
    return db.execute(
        "SELECT * FROM verification_history WHERE id = ?",
        (record_id,),
    ).fetchone()


def get_dashboard_metrics(user_id=None):
    db = get_db()
    base_query = "FROM verification_history"
    params = []
    if user_id:
        base_query += " WHERE user_id = ?"
        params.append(user_id)

    total = db.execute(f"SELECT COUNT(*) {base_query}", params).fetchone()[0]
    low_risk = db.execute(f"SELECT COUNT(*) {base_query} {'AND' if user_id else 'WHERE'} risk_score < 30", params).fetchone()[0]
    suspicious = db.execute(f"SELECT COUNT(*) {base_query} {'AND' if user_id else 'WHERE'} risk_score >= 30 AND risk_score < 60", params).fetchone()[0]
    high_risk = db.execute(f"SELECT COUNT(*) {base_query} {'AND' if user_id else 'WHERE'} risk_score >= 60", params).fetchone()[0]
    avg_score_row = db.execute(f"SELECT AVG(risk_score) {base_query} {'AND' if user_id else 'WHERE'} risk_score IS NOT NULL", params).fetchone()[0]
    avg_score = round(avg_score_row, 1) if avg_score_row is not None else 0.0

    recent_records = db.execute(f"""
        SELECT id, filename, stored_filename, verified_at, status, risk_score, sha256
        {base_query}
        ORDER BY id DESC
        LIMIT 6
    """, params).fetchall()

    return {
        "total": total,
        "low_risk": low_risk,
        "suspicious": suspicious,
        "high_risk": high_risk,
        "avg_score": avg_score,
        "recent_records": recent_records,
    }


# ==================================================
# AUTHENTICATION ROUTES
# ==================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    # Demo 1-click login handler
    if request.args.get("demo") == "1":
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", ("analyst",)).fetchone()
        if user:
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["full_name"] = user["full_name"]
            session["role"] = user["role"]
            flash("Welcome, Chief Security Analyst! Signed in via Demo Mode.")
            return redirect(url_for("dashboard"))

    if request.method == "POST":
        identifier = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not identifier or not password:
            flash("Please enter both username/email and password.")
            return render_template("login.html")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (identifier, identifier),
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["full_name"] = user["full_name"]
            session["role"] = user["role"]
            flash(f"Welcome back, {user['full_name'] or user['username']}!")
            next_url = request.args.get("next")
            return redirect(next_url or url_for("dashboard"))
        else:
            flash("Invalid credentials. Please verify your username and password.")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        full_name = request.form.get("full_name", "").strip()
        role = request.form.get("role", "Security Analyst").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not email or not password:
            flash("Username, email, and password are required.")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters long.")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.")
            return render_template("register.html")

        db = get_db()
        existing = db.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email),
        ).fetchone()

        if existing:
            flash("A user with this username or email already exists.")
            return render_template("register.html")

        hashed = generate_password_hash(password)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cur = db.execute("""
            INSERT INTO users (username, email, password_hash, full_name, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (username, email, hashed, full_name or username, role, now))
        db.commit()

        new_user_id = cur.lastrowid
        session.clear()
        session["user_id"] = new_user_id
        session["username"] = username
        session["full_name"] = full_name or username
        session["role"] = role

        flash("Account created successfully! Welcome to AEGISTID.")
        return redirect(url_for("dashboard"))

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out safely.")
    return redirect(url_for("home"))


# ==================================================
# DASHBOARD & HOMEPAGE
# ==================================================

@app.route("/")
def home():
    """Public landing page showcasing the AEGISTID security platform."""
    user = get_current_user()
    return render_template("index.html", user=user)


@app.route("/dashboard")
@login_required
def dashboard():
    """Cybersecurity Command Operations Dashboard."""
    user = get_current_user()
    metrics = get_dashboard_metrics(user_id=user["id"])
    return render_template(
        "dashboard.html",
        user=user,
        metrics=metrics,
    )


# ==================================================
# DOCUMENT UPLOAD & SCREENING PIPELINE
# ==================================================

@app.route("/upload", methods=["POST"])
def upload_document():
    # Seamless first-time testing: Auto-authenticate demo analyst if not signed in
    if not session.get("user_id"):
        db = get_db()
        demo_user = db.execute("SELECT * FROM users WHERE username = ?", ("analyst",)).fetchone()
        if demo_user:
            session["user_id"] = demo_user["id"]
            session["username"] = demo_user["username"]
            session["full_name"] = demo_user["full_name"]
            session["role"] = demo_user["role"]

    document_file = request.files.get("document")
    signature_file = request.files.get("signature")

    if not document_file or not document_file.filename:
        flash("Please select a document image or PDF to screen.")
        return redirect(url_for("dashboard"))

    if not allowed_file(document_file.filename):
        flash("Allowed file types: JPG, JPEG, PNG, WEBP, and PDF.")
        return redirect(url_for("dashboard"))

    user = get_current_user()
    original_filename = Path(document_file.filename).name
    notices = []

    # -------------------------------------------------------------
    # STEP 1: SAVE & NORMALIZE UPLOADED CREDENTIAL
    # -------------------------------------------------------------
    try:
        stored_path_str = save_document(document_file, destination_folder=UPLOAD_FOLDER)
        stored_path = Path(stored_path_str).resolve()
        if not stored_path.is_file() or stored_path.stat().st_size == 0:
            raise ValueError("Document file saved was empty or unreadable.")
    except Exception as exc:
        print(f"[AEGISTID] Document upload failure: {exc}")
        flash(f"Upload processing failed: {exc}")
        return redirect(url_for("dashboard"))

    # -------------------------------------------------------------
    # STEP 2: SAVE OPTIONAL SPECIMEN SIGNATURE
    # -------------------------------------------------------------
    signature_path = None
    if signature_file and signature_file.filename:
        if allowed_file(signature_file.filename):
            try:
                sig_saved_str = save_document(signature_file, destination_folder=UPLOAD_FOLDER)
                signature_path = Path(sig_saved_str).resolve()
            except Exception as exc:
                notices.append(f"Optional reference signature could not be saved: {exc}")
                signature_path = None
        else:
            notices.append("Reference signature ignored: Format must be JPG, PNG, or WEBP.")

    # -------------------------------------------------------------
    # STEP 3: CRYPTOGRAPHIC INTEGRITY HASH (SHA-256)
    # -------------------------------------------------------------
    try:
        sha256_value = calculate_sha256(str(stored_path))
    except Exception as exc:
        sha256_value = None
        notices.append(f"SHA-256 integrity calculation notice: {exc}")

    # -------------------------------------------------------------
    # STEP 4: PREPROCESS CREDENTIAL IMAGE
    # -------------------------------------------------------------
    try:
        processed_path_str = preprocess_document(str(stored_path))
        processed_path = Path(processed_path_str).resolve()
    except Exception as exc:
        print(f"[AEGISTID] Preprocessing fallback: {exc}")
        notices.append(f"Preprocessing notice: {exc}")
        processed_path = stored_path

    # -------------------------------------------------------------
    # STEP 5: OCR & MRZ EXTRACTION (ICAO 9303)
    # -------------------------------------------------------------
    try:
        ocr_result = extract_document_data(str(processed_path))
    except Exception as exc:
        print(f"[AEGISTID] OCR extraction error: {exc}")
        ocr_result = {"raw_text": "", "error": str(exc), "mrz": [], "passport": False}

    # -------------------------------------------------------------
    # STEP 6: CREDENTIAL & DATE VALIDATION
    # -------------------------------------------------------------
    try:
        validation_result = validate_document(ocr_result)
    except Exception as exc:
        print(f"[AEGISTID] Validation error: {exc}")
        validation_result = {"valid": False, "status": "Invalid", "error": str(exc)}

    # -------------------------------------------------------------
    # STEP 7: AI TAMPER DETECTION (ELA & NOISE VARIANCE)
    # -------------------------------------------------------------
    try:
        tamper_result = detect_tampering(str(processed_path))
    except Exception as exc:
        print(f"[AEGISTID] Tamper screening error: {exc}")
        tamper_result = {"tampered": False, "error": str(exc)}

    # -------------------------------------------------------------
    # STEP 8: FACIAL PORTRAIT DETECTION
    # -------------------------------------------------------------
    try:
        face_result = detect_faces(str(processed_path))
    except Exception as exc:
        print(f"[AEGISTID] Face detection error: {exc}")
        face_result = {"verified": False, "error": str(exc)}

    # -------------------------------------------------------------
    # STEP 9: SIGNATURE ANALYSIS
    # -------------------------------------------------------------
    try:
        sig_ref_str = str(signature_path) if signature_path else None
        signature_result = verify_signature(str(processed_path), sig_ref_str)
    except Exception as exc:
        print(f"[AEGISTID] Signature analysis error: {exc}")
        signature_result = {"verified": None, "error": str(exc)}

    # -------------------------------------------------------------
    # STEP 10: METADATA & FORENSIC TAG INSPECTION
    # -------------------------------------------------------------
    try:
        metadata_result = analyze_metadata(str(stored_path))
    except Exception as exc:
        print(f"[AEGISTID] Metadata error: {exc}")
        metadata_result = {"metadata_found": False, "error": str(exc)}

    # -------------------------------------------------------------
    # STEP 11: COMPOSITE RISK CALCULATION
    # -------------------------------------------------------------
    risk_result = calculate_risk(
        validation_result=validation_result,
        tamper_result=tamper_result,
        face_result=face_result,
        signature_result=signature_result,
        metadata_result=metadata_result,
        hash_result=sha256_value,
    )

    overall_status = risk_result.get("status", "ANALYSIS COMPLETED")
    risk_score = risk_result.get("risk_score", 0)

    # -------------------------------------------------------------
    # STEP 12: COMPILE REPORT & COMMIT TO DATABASE
    # -------------------------------------------------------------
    details = {
        "original_filename": original_filename,
        "ocr_result": ocr_result,
        "validation_result": validation_result,
        "tamper_result": tamper_result,
        "face_result": face_result,
        "signature_result": signature_result,
        "metadata_result": metadata_result,
        "risk_result": risk_result,
        "sha256": sha256_value,
        "notices": notices,
    }

    record_id = save_history_record(
        user_id=user["id"],
        filename=original_filename,
        stored_filename=stored_path.name,
        processed_filename=processed_path.name if processed_path else None,
        status=overall_status,
        risk_score=risk_score,
        sha256_value=sha256_value,
        details=details,
    )

    flash("Document screening completed successfully.")
    return redirect(url_for("view_verification", record_id=record_id))


# ==================================================
# VERIFICATION REPORT & DOCUMENT VIEWS
# ==================================================

@app.route("/verification/<int:record_id>")
@login_required
def view_verification(record_id):
    """Full executive verification report with interactive forensics."""
    user = get_current_user()
    record = get_history_record(record_id)
    if not record:
        abort(404)

    try:
        details = json.loads(record["details_json"] or "{}")
    except Exception:
        details = {}

    document_url = url_for("uploaded_file", filename=record["stored_filename"])
    processed_url = None
    if record["processed_filename"] and (PROCESSED_FOLDER / record["processed_filename"]).is_file():
        processed_url = url_for("processed_file", filename=record["processed_filename"])

    # Extract ELA and Face visualization URLs if present
    tamper_info = details.get("tamper_result", {})
    ela_url = None
    if tamper_info.get("ela_image"):
        ela_file = PROCESSED_FOLDER / tamper_info["ela_image"]
        if ela_file.is_file():
            ela_url = url_for("processed_file", filename=tamper_info["ela_image"])

    face_info = details.get("face_result", {})
    face_url = None
    if face_info.get("face_image"):
        face_file = PROCESSED_FOLDER / face_info["face_image"]
        if face_file.is_file():
            face_url = url_for("processed_file", filename=face_info["face_image"])

    sig_info = details.get("signature_result", {})
    extracted_sig_url = None
    if sig_info.get("extracted_signature_image"):
        sig_file = PROCESSED_FOLDER / sig_info["extracted_signature_image"]
        if sig_file.is_file():
            extracted_sig_url = url_for("processed_file", filename=sig_info["extracted_signature_image"])

    return render_template(
        "result.html",
        user=user,
        record=record,
        record_id=record["id"],
        filename=record["filename"],
        stored_filename=record["stored_filename"],
        processed_filename=record["processed_filename"],
        document_url=document_url,
        processed_url=processed_url,
        ela_url=ela_url,
        face_url=face_url,
        extracted_sig_url=extracted_sig_url,
        verified_at=record["verified_at"],
        status=record["status"],
        risk_score=record["risk_score"],
        sha256=record["sha256"] or "Not available",
        ocr_result=details.get("ocr_result", {}),
        validation_result=details.get("validation_result", {}),
        tamper_result=tamper_info,
        face_result=face_info,
        signature_result=sig_info,
        metadata_result=details.get("metadata_result", {}),
        risk_result=details.get("risk_result", {}),
        notices=details.get("notices", []),
        details=details,
    )


@app.route("/verification/<int:record_id>/print")
@login_required
def print_verification(record_id):
    """Printable official report suitable for browser Print to PDF."""
    record = get_history_record(record_id)
    if not record:
        abort(404)

    try:
        details = json.loads(record["details_json"] or "{}")
    except Exception:
        details = {}

    document_url = url_for("uploaded_file", filename=record["stored_filename"])
    return render_template(
        "result.html",
        print_mode=True,
        user=get_current_user(),
        record=record,
        record_id=record["id"],
        filename=record["filename"],
        document_url=document_url,
        verified_at=record["verified_at"],
        status=record["status"],
        risk_score=record["risk_score"],
        sha256=record["sha256"] or "Not available",
        ocr_result=details.get("ocr_result", {}),
        validation_result=details.get("validation_result", {}),
        tamper_result=details.get("tamper_result", {}),
        face_result=details.get("face_result", {}),
        signature_result=details.get("signature_result", {}),
        metadata_result=details.get("metadata_result", {}),
        risk_result=details.get("risk_result", {}),
        notices=details.get("notices", []),
        details=details,
    )


@app.route("/document/<int:record_id>")
@login_required
def document_preview(record_id):
    """High-resolution credential inspector view."""
    record = get_history_record(record_id)
    if not record:
        abort(404)

    document_url = url_for("uploaded_file", filename=record["stored_filename"])
    return render_template(
        "document_preview.html",
        user=get_current_user(),
        record=record,
        document_url=document_url,
    )


# ==================================================
# VERIFICATION HISTORY & AUDIT LOG
# ==================================================

@app.route("/history")
@login_required
def history():
    user = get_current_user()
    db = get_db()

    query = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "").strip()

    sql = "SELECT * FROM verification_history WHERE 1=1"
    params = []

    if query:
        sql += " AND (filename LIKE ? OR sha256 LIKE ?)"
        params.extend([f"%{query}%", f"%{query}%"])

    if status_filter:
        sql += " AND status = ?"
        params.append(status_filter)

    sql += " ORDER BY id DESC"
    records = db.execute(sql, params).fetchall()

    return render_template(
        "history.html",
        user=user,
        records=records,
        search_query=query,
        status_filter=status_filter,
    )


@app.route("/history/delete/<int:record_id>", methods=["POST"])
@login_required
def delete_record(record_id):
    db = get_db()
    db.execute("DELETE FROM verification_history WHERE id = ?", (record_id,))
    db.commit()
    flash(f"Verification record #{record_id} was removed.")
    return redirect(url_for("history"))


# ==================================================
# STATIC FILE SERVERS
# ==================================================

@app.route("/uploaded-file/<path:filename>")
@login_required
def uploaded_file(filename):
    safe_name = Path(filename).name
    target = UPLOAD_FOLDER / safe_name
    if not target.is_file():
        abort(404)
    return send_from_directory(str(UPLOAD_FOLDER), safe_name)


@app.route("/processed-file/<path:filename>")
@login_required
def processed_file(filename):
    safe_name = Path(filename).name
    target = PROCESSED_FOLDER / safe_name
    if not target.is_file():
        abort(404)
    return send_from_directory(str(PROCESSED_FOLDER), safe_name)


# ==================================================
# ERROR HANDLERS
# ==================================================

@app.errorhandler(404)
def not_found_error(error):
    return render_template(
        "result.html",
        error_title="404 — Security Workspace Not Found",
        error_description="The requested verification record or resource does not exist.",
    ), 404


@app.errorhandler(413)
def request_entity_too_large(error):
    flash("Upload exceeds maximum allowed size (10 MB).")
    return redirect(url_for("dashboard"))


@app.errorhandler(500)
def internal_error(error):
    return render_template(
        "result.html",
        error_title="500 — Internal Processing Anomaly",
        error_description="An unexpected error occurred during security pipeline execution.",
    ), 500


# ==================================================
# APPLICATION ENTRYPOINT
# ==================================================

if __name__ == "__main__":
    print("==================================================")
    print("  AEGISTID — Intelligent Document Security Platform")
    print("  Server launching at http://127.0.0.1:5000")
    print("  Default Demo Account: analyst / Password@123")
    print("==================================================")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False,
    )
