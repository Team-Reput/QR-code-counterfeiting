import os
import json
import csv
import base64
import urllib.parse
from datetime import datetime, date
from typing import Optional, Tuple, Dict, Any
import threading

import psycopg2
from psycopg2.extras import RealDictCursor

import qrcode
from PIL import Image, ImageDraw

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

from geopy.geocoders import Nominatim

from cryptography.hazmat.primitives import serialization


# ================================================================
#                        CONFIG
# ================================================================
DB_CONFIG = {
    "host": os.getenv("PGHOST", "postgresdb-development.cbeecasywb59.ap-south-1.rds.amazonaws.com"),
    "port": int(os.getenv("PGPORT", "5432")),
    "user": os.getenv("PGUSER", "postgres"),
    "password": os.getenv("PGPASSWORD", "Postgres"),
    "database": os.getenv("PGDATABASE", "Reput_Tracing"),
}

# Keep in sync with QR generator
QR_BOX_SIZE = int(os.getenv("QR_BOX_SIZE", "10"))
QR_BORDER = int(os.getenv("QR_BORDER", "2"))
QR_ERROR_CORRECTION = qrcode.constants.ERROR_CORRECT_H

# Brand filter used in generator fetch
BRAND_ID = int(os.getenv("BRAND_ID", "222"))

# Optional scan log table (won't crash if missing)
SCAN_LOG_TABLE = os.getenv("SCAN_LOG_TABLE", "dbo.qr_scan_logs")

# Ownership table
OWNERSHIP_TABLE = os.getenv("OWNERSHIP_TABLE", "dbo.product_ownership")

# Public key path (Ed25519 public key PEM)
PUBLIC_KEY_PATH = os.getenv("PUBLIC_KEY_PATH", "public_key.pem")

# CSV file for OTP and ownership data (instead of database)
OTP_CSV_FILE = os.getenv("OTP_CSV_FILE", os.path.join(os.path.dirname(__file__), "otp_codes.csv"))

# Lock for thread-safe CSV operations
csv_lock = threading.Lock()


# ================================================================
#                        JSON ENCODER
# ================================================================
class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return super().default(obj)


def canonical_product_json(row: Dict[str, Any]) -> bytes:
    """
    Must match generator:
      json.dumps(row, cls=DateTimeEncoder, sort_keys=True, separators=(",", ":"))
    """
    canonical = json.dumps(row, cls=DateTimeEncoder, sort_keys=True, separators=(",", ":"))
    return canonical.encode("utf-8")


# ================================================================
#                        LOAD PUBLIC KEY
# ================================================================
def load_public_key_from_pem(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


PUBLIC_KEY = load_public_key_from_pem(PUBLIC_KEY_PATH)


# ================================================================
#                        TOKEN HELPERS
# ================================================================
def extract_token(token_or_url: str) -> Optional[str]:
    """
    Accepts:
      - raw token string
      - full scanned URL that contains ?token=...
    Returns token (string) or None.
    """
    if not token_or_url:
        return None

    text = token_or_url.strip()
    if "://" in text or text.startswith("http"):
        try:
            parsed = urllib.parse.urlparse(text)
            q = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            return q.get("token")
        except Exception:
            return None

    # assume raw token
    return text


def b64url_to_bytes(signature_b64url: str) -> bytes:
    # generator strips "=" padding
    padded = signature_b64url + "=" * (-len(signature_b64url) % 4)
    return base64.urlsafe_b64decode(padded.encode("utf-8"))


def verify_ed25519_signature(public_key, data: bytes, token_b64url: str) -> bool:
    """
    Ed25519 verify:
      public_key.verify(signature, data)
    """
    try:
        sig = b64url_to_bytes(token_b64url)
        public_key.verify(sig, data)
        return True
    except Exception:
        return False


# ================================================================
#                        DATABASE
# ================================================================
def db_connect():
    return psycopg2.connect(**DB_CONFIG)


def fetch_candidate_rows() -> list:
    """
    Must match generator selection:
      FROM dbo.batchnumbers WHERE brandid=<BRAND_ID> AND is_submit=1
    """
    query = """
        SELECT *
        FROM dbo.batchnumbers
        WHERE brandid = %s
          AND is_submit = 1
    """
    conn = db_connect()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, (BRAND_ID,))
            return cur.fetchall()
    finally:
        conn.close()


def find_row_by_token(token: str) -> Tuple[Optional[Dict[str, Any]], bool]:
    """
    Because the QR contains ONLY the signature token (no id fields),
    we locate the matching product row by verifying signature over each row's canonical JSON.
    Stop at the first match.
    """
    rows = fetch_candidate_rows()
    for row in rows:
        data = canonical_product_json(row)
        if verify_ed25519_signature(PUBLIC_KEY, data, token):
            return row, True
    return None, False


# ================================================================
#                 MICRO-PATTERN (MATCH GENERATOR)
# ================================================================
def make_qr_image(payload_text: str) -> Image.Image:
    qr = qrcode.QRCode(
        version=None,
        error_correction=QR_ERROR_CORRECTION,
        box_size=QR_BOX_SIZE,
        border=QR_BORDER,
    )
    qr.add_data(payload_text)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white").convert("RGB")


def apply_micro_pattern_top_and_right(qr_img: Image.Image) -> Image.Image:
    """
    Must match generator:
      top strip thickness 4, right strip thickness 4
      white dot at (cx - offset//2, cy + offset//2) for black modules
      skipping finder/timing/quiet zones
    """
    img = qr_img.convert("RGB")
    draw = ImageDraw.Draw(img)

    w, _ = img.size
    modules = w // QR_BOX_SIZE

    TOP_STRIP_THICKNESS = 4
    RIGHT_STRIP_THICKNESS = 4

    def in_quiet_zone(mx: int, my: int) -> bool:
        return mx < QR_BORDER or my < QR_BORDER or mx >= (modules - QR_BORDER) or my >= (modules - QR_BORDER)

    def in_finder_zone(mx: int, my: int) -> bool:
        if mx < (QR_BORDER + 9) and my < (QR_BORDER + 9):
            return True
        if mx >= (modules - QR_BORDER - 9) and my < (QR_BORDER + 9):
            return True
        if mx < (QR_BORDER + 9) and my >= (modules - QR_BORDER - 9):
            return True
        return False

    timing_row = QR_BORDER + 6
    timing_col = QR_BORDER + 6

    dot_r = max(1, QR_BOX_SIZE // 8)
    offset = max(1, QR_BOX_SIZE // 3)

    top_y_start = QR_BORDER
    top_y_end = min(modules - QR_BORDER, QR_BORDER + TOP_STRIP_THICKNESS)

    right_x_start = max(QR_BORDER, modules - QR_BORDER - RIGHT_STRIP_THICKNESS)
    right_x_end = modules - QR_BORDER

    for my in range(QR_BORDER, modules - QR_BORDER):
        for mx in range(QR_BORDER, modules - QR_BORDER):
            if in_quiet_zone(mx, my) or in_finder_zone(mx, my):
                continue
            if mx == timing_col or my == timing_row:
                continue

            in_top_strip = top_y_start <= my < top_y_end
            in_right_strip = right_x_start <= mx < right_x_end
            if not (in_top_strip or in_right_strip):
                continue

            x0 = mx * QR_BOX_SIZE
            y0 = my * QR_BOX_SIZE
            cx = x0 + QR_BOX_SIZE // 2
            cy = y0 + QR_BOX_SIZE // 2

            r, g, b = img.getpixel((cx, cy))
            if (r, g, b) == (0, 0, 0):
                dx = cx - offset // 2
                dy = cy + offset // 2
                draw.ellipse((dx - dot_r, dy - dot_r, dx + dot_r, dy + dot_r), fill=(255, 255, 255))

    return img


def crop_qr_square(img: Image.Image) -> Image.Image:
    """
    Generator may append a bottom white strip (OTP text).
    Crop to a square using top-left min(w,h).
    """
    img = img.convert("RGB")
    w, h = img.size
    side = min(w, h)
    return img.crop((0, 0, side, side))


def verify_micro_pattern_for_token(scanned_qr_img: Image.Image, scanned_url_or_token: str) -> Tuple[bool, float]:
    """
    Robust approach:
    - regenerate expected QR (base + patterned) from scanned URL
    - crop scanned image to QR square and resize to expected size
    - validate dot pixels in top+right strips where BASE module is black
    """
    token = extract_token(scanned_url_or_token)
    if not token:
        return False, 0.0

    payload_text = scanned_url_or_token.strip()
    if "://" not in payload_text and not payload_text.startswith("http"):
        return False, 0.0  # need full URL for correct module layout

    expected_base = make_qr_image(payload_text)
    expected_patterned = apply_micro_pattern_top_and_right(expected_base.copy())

    scanned_square = crop_qr_square(scanned_qr_img)
    scanned_resized = scanned_square.resize(expected_patterned.size, Image.NEAREST)

    w, _ = expected_base.size
    modules = w // QR_BOX_SIZE

    TOP_STRIP_THICKNESS = 4
    RIGHT_STRIP_THICKNESS = 4

    timing_row = QR_BORDER + 6
    timing_col = QR_BORDER + 6

    dot_r = max(1, QR_BOX_SIZE // 8)
    offset = max(1, QR_BOX_SIZE // 3)

    def in_quiet_zone(mx: int, my: int) -> bool:
        return mx < QR_BORDER or my < QR_BORDER or mx >= (modules - QR_BORDER) or my >= (modules - QR_BORDER)

    def in_finder_zone(mx: int, my: int) -> bool:
        if mx < (QR_BORDER + 9) and my < (QR_BORDER + 9):
            return True
        if mx >= (modules - QR_BORDER - 9) and my < (QR_BORDER + 9):
            return True
        if mx < (QR_BORDER + 9) and my >= (modules - QR_BORDER - 9):
            return True
        return False

    top_y_start = QR_BORDER
    top_y_end = min(modules - QR_BORDER, QR_BORDER + TOP_STRIP_THICKNESS)

    right_x_start = max(QR_BORDER, modules - QR_BORDER - RIGHT_STRIP_THICKNESS)
    right_x_end = modules - QR_BORDER

    checked = 0
    mismatches = 0

    for my in range(QR_BORDER, modules - QR_BORDER):
        for mx in range(QR_BORDER, modules - QR_BORDER):
            if in_quiet_zone(mx, my) or in_finder_zone(mx, my):
                continue
            if mx == timing_col or my == timing_row:
                continue

            in_top_strip = top_y_start <= my < top_y_end
            in_right_strip = right_x_start <= mx < right_x_end
            if not (in_top_strip or in_right_strip):
                continue

            x0 = mx * QR_BOX_SIZE
            y0 = my * QR_BOX_SIZE
            cx = x0 + QR_BOX_SIZE // 2
            cy = y0 + QR_BOX_SIZE // 2

            # only black modules in BASE should have dot
            r0, g0, b0 = expected_base.getpixel((cx, cy))
            if (r0, g0, b0) != (0, 0, 0):
                continue

            dx = cx - offset // 2
            dy = cy + offset // 2

            neighborhood = []
            for ox in range(-dot_r, dot_r + 1):
                for oy in range(-dot_r, dot_r + 1):
                    px = min(max(dx + ox, 0), w - 1)
                    py = min(max(dy + oy, 0), w - 1)
                    neighborhood.append(scanned_resized.getpixel((px, py)))

            light = sum(1 for (r, g, b) in neighborhood if r > 200 and g > 200 and b > 200)
            checked += 1
            if light < max(3, len(neighborhood) // 6):
                mismatches += 1

    if checked == 0:
        return False, 0.0

    score = 100.0 * (checked - mismatches) / checked
    ok = score >= 60.0  # relaxed threshold for real-world scans
    return ok, score


# ================================================================
#                    COUNTRY DETECTION (GPS)
# ================================================================
def detect_country(lat, lng):
    if lat is None or lng is None:
        return "Unknown"
    try:
        geolocator = Nominatim(user_agent="qr_verifier")
        location = geolocator.reverse((lat, lng), language="en")
        if not location:
            return "Unknown"
        return location.raw.get("address", {}).get("country", "Unknown")
    except Exception:
        return "Unknown"


# ================================================================
#                    SCAN LOGGING & HISTORY
# ================================================================
def ensure_scan_log_table():
    """
    Create the scan log table if it doesn't exist, and add any
    missing columns if the table was created by an older version.
    Best-effort; won't crash the app on failure.
    """
    try:
        conn = db_connect()
        try:
            with conn.cursor() as cur:
                cur.execute(f"""
                    CREATE TABLE IF NOT EXISTS {SCAN_LOG_TABLE} (
                        id SERIAL PRIMARY KEY,
                        token TEXT NOT NULL,
                        batch_id TEXT,
                        status TEXT,
                        country TEXT,
                        lat DOUBLE PRECISION,
                        lng DOUBLE PRECISION,
                        device TEXT,
                        device_make TEXT,
                        device_model TEXT,
                        scanned_at TIMESTAMP DEFAULT NOW()
                    )
                """)

                # Add columns that may be missing from an older table
                for col, col_type in [
                    ("batch_id", "TEXT"),
                    ("device", "TEXT"),
                    ("device_make", "TEXT"),
                    ("device_model", "TEXT"),
                ]:
                    try:
                        cur.execute(f"""
                            ALTER TABLE {SCAN_LOG_TABLE}
                            ADD COLUMN IF NOT EXISTS {col} {col_type}
                        """)
                    except Exception:
                        pass  # column already exists or DB doesn't support IF NOT EXISTS

            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"[WARN] ensure_scan_log_table failed: {e}")


def safe_log_scan(token: str, status: str, country: str,
                  lat: Optional[float], lng: Optional[float],
                  device: str = "Unknown", batch_id: str = "",
                  device_make: str = "Unknown", device_model: str = "Unknown"):
    """
    Best-effort logging. Records every scan with device make/model and batch info.
    """
    try:
        conn = db_connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO {SCAN_LOG_TABLE}
                        (token, batch_id, status, country, lat, lng, device,
                         device_make, device_model, scanned_at)
                    VALUES
                        (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    """,
                    (token, batch_id, status, country, lat, lng, device,
                     device_make, device_model),
                )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"[WARN] safe_log_scan failed: {e}")


def get_scan_history(token: str) -> Dict[str, Any]:
    """
    Retrieve scan history for a given token:
      - total scan count
      - list of recent scans (location, device, timestamp)
    """
    history = {
        "scan_count": 0,
        "recent_scans": [],
    }
    try:
        conn = db_connect()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Total scan count
                cur.execute(
                    f"SELECT COUNT(*) AS cnt FROM {SCAN_LOG_TABLE} WHERE token = %s",
                    (token,),
                )
                row = cur.fetchone()
                history["scan_count"] = row["cnt"] if row else 0

                # Recent scans (last 10)
                cur.execute(
                    f"""
                    SELECT country, device, device_make, device_model,
                           scanned_at, lat, lng
                    FROM {SCAN_LOG_TABLE}
                    WHERE token = %s
                    ORDER BY scanned_at DESC
                    LIMIT 10
                    """,
                    (token,),
                )
                history["recent_scans"] = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()
    except Exception as e:
        print(f"[WARN] get_scan_history failed: {e}")

    return history


# ================================================================
#                    OWNERSHIP MANAGEMENT
# ================================================================
def ensure_ownership_table():
    try:
        conn = db_connect()
        try:
            with conn.cursor() as cur:
                cur.execute(f"""
                    CREATE TABLE IF NOT EXISTS {OWNERSHIP_TABLE} (
                        id SERIAL PRIMARY KEY,
                        token TEXT NOT NULL UNIQUE,
                        product_id TEXT,
                        batch_id TEXT,
                        otp_code TEXT NOT NULL,
                        owner_name TEXT NOT NULL,
                        owner_phone TEXT NOT NULL,
                        device_fingerprint TEXT NOT NULL,
                        device_make TEXT,
                        device_model TEXT,
                        claimed_at TIMESTAMP DEFAULT NOW()
                    )
                """)
                for col, col_type in [
                    ("device_fingerprint", "TEXT"),
                    ("device_make", "TEXT"),
                    ("device_model", "TEXT"),
                ]:
                    try:
                        cur.execute(f"""
                            ALTER TABLE {OWNERSHIP_TABLE}
                            ADD COLUMN IF NOT EXISTS {col} {col_type}
                        """)
                    except Exception:
                        pass
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"[WARN] ensure_ownership_table failed: {e}")


def get_ownership(token: str) -> Optional[Dict[str, Any]]:
    """
    Get ownership information from CSV file by token or signature_token.
    CSV structure: batch_id, signature_token, otp_code (+ ownership columns)
    """
    try:
        with csv_lock:
            if not os.path.exists(OTP_CSV_FILE):
                return None

            with open(OTP_CSV_FILE, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Match by stored token or signature_token (from QR code)
                    row_token = row.get('token', '').strip()
                    row_signature_token = row.get('signature_token', '').strip()

                    if (row_token and row_token == token) or (row_signature_token and row_signature_token == token):
                        # Check if ownership has been claimed
                        if row.get('device_fingerprint', '').strip():
                            return {
                                'token': row_token or row_signature_token,
                                'product_id': row.get('batch_id', ''),
                                'batch_id': row.get('batch_id', ''),
                                'owner_name': row.get('owner_name', ''),
                                'owner_phone': row.get('owner_phone', ''),
                                'device_fingerprint': row.get('device_fingerprint', ''),
                                'device_make': row.get('device_make', ''),
                                'device_model': row.get('device_model', ''),
                                'claimed_at': row.get('claimed_at', ''),
                            }
            return None
    except Exception as e:
        print(f"[WARN] get_ownership failed: {e}")
        return None


def get_ownership_by_product(product_id: str = None, batch_id: str = None) -> Optional[Dict[str, Any]]:
    """
    Get ownership information from CSV file by product_id or batch_id.
    CSV structure: batch_id, signature_token, otp_code (+ ownership columns)
    """
    try:
        with csv_lock:
            if not os.path.exists(OTP_CSV_FILE):
                return None

            with open(OTP_CSV_FILE, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    row_batch_id = str(row.get('batch_id', '')).strip()

                    # Match by product_id (as batch_id) or batch_id
                    if ((product_id and row_batch_id == str(product_id).strip()) or
                        (batch_id and row_batch_id == str(batch_id).strip())):
                        # Check if ownership has been claimed
                        if row.get('device_fingerprint', '').strip():
                            return {
                                'token': row.get('token', ''),
                                'product_id': row_batch_id,
                                'batch_id': row_batch_id,
                                'owner_name': row.get('owner_name', ''),
                                'owner_phone': row.get('owner_phone', ''),
                                'device_fingerprint': row.get('device_fingerprint', ''),
                                'device_make': row.get('device_make', ''),
                                'device_model': row.get('device_model', ''),
                                'claimed_at': row.get('claimed_at', ''),
                            }
            return None
    except Exception as e:
        print(f"[WARN] get_ownership_by_product failed: {e}")
        return None


def get_otp_for_product(product_id: str = None, batch_id: str = None, token: str = None) -> Optional[str]:
    """
    Get OTP code for a product from CSV file.
    CSV structure: batch_id, signature_token, otp_code
    Tries: batch_id -> signature_token lookup in CSV
    """
    try:
        with csv_lock:
            if not os.path.exists(OTP_CSV_FILE):
                print(f"[WARN] OTP CSV file not found: {OTP_CSV_FILE}")
                return None

            with open(OTP_CSV_FILE, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Try matching by batch_id (primary lookup)
                    if batch_id and str(row.get('batch_id', '')).strip() == str(batch_id).strip():
                        otp = row.get('otp_code', '').strip()
                        if otp:
                            print(f"[DEBUG] Found OTP for batch_id {batch_id}: {otp}")
                            return otp

                    # Try matching by signature_token (from QR code)
                    if token and str(row.get('signature_token', '')).strip() == str(token).strip():
                        otp = row.get('otp_code', '').strip()
                        if otp:
                            print(f"[DEBUG] Found OTP for signature_token")
                            return otp

                    # Fallback: try product_id as batch_id
                    if product_id and str(row.get('batch_id', '')).strip() == str(product_id).strip():
                        otp = row.get('otp_code', '').strip()
                        if otp:
                            print(f"[DEBUG] Found OTP for product_id (as batch_id) {product_id}: {otp}")
                            return otp

        print(f"[DEBUG] No OTP found for product_id={product_id}, batch_id={batch_id}, token={token[:20] if token else None}...")
        return None
    except Exception as e:
        print(f"[WARN] get_otp_for_product failed: {e}")
        return None


def claim_ownership(token: str, product_id: str, batch_id: str,
                    otp_code: str, owner_name: str, owner_phone: str,
                    device_fingerprint: str, device_make: str = "",
                    device_model: str = "") -> Tuple[bool, str]:
    """
    Claim ownership by updating the CSV file with owner information.
    CSV structure: batch_id, signature_token, otp_code (+ ownership columns added on claim)
    """
    try:
        with csv_lock:
            if not os.path.exists(OTP_CSV_FILE):
                return False, "OTP data file not found."

            # Read all rows
            rows = []
            fieldnames = None
            with open(OTP_CSV_FILE, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                fieldnames = list(reader.fieldnames) if reader.fieldnames else []
                rows = list(reader)

            # Add ownership columns if they don't exist
            ownership_columns = ['token', 'owner_name', 'owner_phone', 'device_fingerprint',
                               'device_make', 'device_model', 'claimed_at']
            for col in ownership_columns:
                if col not in fieldnames:
                    fieldnames.append(col)

            # Find the matching row and check if already claimed
            found = False
            for row in rows:
                row_batch_id = str(row.get('batch_id', '')).strip()
                row_signature_token = str(row.get('signature_token', '')).strip()

                # Match by batch_id or signature_token
                match_by_batch = batch_id and row_batch_id == str(batch_id).strip()
                match_by_token = token and row_signature_token == str(token).strip()
                match_by_product = product_id and row_batch_id == str(product_id).strip()

                if match_by_batch or match_by_token or match_by_product:
                    found = True

                    # Check if already claimed
                    if row.get('device_fingerprint', '').strip():
                        return False, "This product has already been claimed."

                    # Update the row with ownership info
                    row['token'] = token  # Store token for future lookups
                    row['owner_name'] = owner_name
                    row['owner_phone'] = owner_phone
                    row['device_fingerprint'] = device_fingerprint
                    row['device_make'] = device_make
                    row['device_model'] = device_model
                    row['claimed_at'] = datetime.now().isoformat()
                    print(f"[DEBUG] Claiming ownership for batch_id={batch_id}")
                    break

            if not found:
                return False, "Product not found in OTP database."

            # Write back all rows with updated fieldnames
            with open(OTP_CSV_FILE, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)

            print(f"[DEBUG] Ownership claimed successfully, CSV updated")
            return True, "Ownership claimed successfully."
    except Exception as e:
        print(f"[WARN] claim_ownership failed: {e}")
        return False, "Failed to claim ownership. Please try again."


def mask_phone(phone: str) -> str:
    if not phone or len(phone) < 5:
        return phone or ""
    return phone[:3] + "*" * (len(phone) - 5) + phone[-2:]


# ================================================================
#                        FLASK APP
# ================================================================
app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app, resources={r"/*": {"origins": "*"}})

# Ensure scan log table exists on startup
ensure_scan_log_table()
ensure_ownership_table()


@app.route("/api/debug/db_schema", methods=["GET"])
def debug_db_schema():
    """
    Debug endpoint to check database schema and sample data.
    Remove this in production!
    """
    try:
        conn = db_connect()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Get column names
                cur.execute("""
                    SELECT column_name, data_type
                    FROM information_schema.columns
                    WHERE table_name = 'batchnumbers'
                    ORDER BY ordinal_position
                """)
                columns = cur.fetchall()

                # Get sample row (first matching row)
                cur.execute(f"""
                    SELECT * FROM dbo.batchnumbers
                    WHERE brandid = %s AND is_submit = 1
                    LIMIT 1
                """, (BRAND_ID,))
                sample_row = cur.fetchone()

                # Get row count
                cur.execute(f"""
                    SELECT COUNT(*) as count FROM dbo.batchnumbers
                    WHERE brandid = %s AND is_submit = 1
                """, (BRAND_ID,))
                row_count = cur.fetchone()

                return jsonify({
                    "columns": [dict(c) for c in columns] if columns else [],
                    "sample_row_keys": list(sample_row.keys()) if sample_row else [],
                    "sample_row": {k: str(v)[:50] for k, v in sample_row.items()} if sample_row else None,
                    "has_product_id": "product_id" in (sample_row or {}),
                    "has_otp_code": "otp_code" in (sample_row or {}),
                    "total_rows": row_count["count"] if row_count else 0,
                    "brand_id": BRAND_ID
                })
        finally:
            conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/debug/csv_otp", methods=["GET"])
def debug_csv_otp():
    """
    Debug endpoint to check CSV OTP data.
    """
    try:
        if not os.path.exists(OTP_CSV_FILE):
            return jsonify({"error": f"CSV file not found: {OTP_CSV_FILE}"}), 404

        rows = []
        with open(OTP_CSV_FILE, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
            for row in reader:
                # Mask sensitive data
                row_copy = dict(row)
                if row_copy.get('owner_phone'):
                    row_copy['owner_phone'] = mask_phone(row_copy['owner_phone'])
                if row_copy.get('device_fingerprint'):
                    row_copy['device_fingerprint'] = row_copy['device_fingerprint'][:8] + '...'
                rows.append(row_copy)

        return jsonify({
            "csv_file": OTP_CSV_FILE,
            "fieldnames": fieldnames,
            "total_rows": len(rows),
            "rows": rows
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health")
def health():
    return jsonify({"ok": True})


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/results")
def results():
    return render_template("results.html")


@app.route("/verify", methods=["POST"])
def verify_qr():
    """
    Expected inputs (form-data):
      - url (always in your case; contains token=...)
      - qr_image (recommended for micro-pattern)
      - lat, lng (optional, for scan logging only)
    """
    url_in = request.form.get("url") or ""
    token_in = request.form.get("token") or ""
    token = extract_token(token_in) or extract_token(url_in)

    if not token:
        return jsonify({
            "status": "FAKE",
            "verified": False,
            "reason": "Missing or invalid verification token. This QR code cannot be authenticated.",
            "product": {},
            "scan_history": {"scan_count": 0, "recent_scans": []},
        }), 400

    # --- Verification: signature + micro-pattern only ---
    matched_row, signature_ok = find_row_by_token(token)

    micro_ok = False
    qr_file = request.files.get("qr_image")
    if qr_file and url_in:
        try:
            qr_img = Image.open(qr_file).convert("RGB")
            micro_ok, _ = verify_micro_pattern_for_token(qr_img, url_in)
        except Exception:
            micro_ok = False

    # Determine final status using signature + micro-pattern
    verified = False
    if not signature_ok:
        final_status = "FAKE"
        reason = "The cryptographic signature on this QR code is invalid. This product could not be matched to any authenticated record in our database. It may be counterfeit."
    elif qr_file and url_in and not micro_ok:
        final_status = "FAKE"
        reason = "The cryptographic signature is valid, but the physical micro-pattern on the QR code does not match the expected pattern. The printed label may have been reproduced or tampered with."
    else:
        final_status = "AUTHENTIC"
        verified = True
        reason = "This product has been verified as authentic. All security checks passed successfully."

    # --- Collect scan metadata for logging (not for verification) ---
    lat = request.form.get("lat")
    lng = request.form.get("lng")
    lat_f = None
    lng_f = None
    country = "Unknown"

    if lat and lng:
        try:
            lat_f = float(lat)
            lng_f = float(lng)
            country = detect_country(lat_f, lng_f)
        except Exception:
            country = "Unknown"

    # Device info
    device = request.headers.get("User-Agent", "Unknown")
    device_make = request.form.get("device_make") or "Unknown"
    device_model = request.form.get("device_model") or "Unknown"

    # Batch ID from matched product row
    batch_id = ""
    if matched_row:
        batch_id = str(matched_row.get("batch", ""))

    # Log this scan
    safe_log_scan(token, final_status, country, lat_f, lng_f, device, batch_id,
                  device_make, device_model)

    # Retrieve scan history for this token
    scan_history = get_scan_history(token)

    # Build product preview with all available fields
    product_preview = {}
    if matched_row:
        # Debug: log available columns
        print(f"[DEBUG] matched_row columns: {list(matched_row.keys())}")

        # Map actual DB column names to display names
        column_mappings = {
            "productid": "product_id",
            "batch_number": "batch",
            "batchid": "batch_id",
            "created_at": "date",
        }

        display_fields = [
            "product_id", "productid", "batch", "batch_number", "batchid",
            "date", "created_at", "brandid", "is_submit",
            "product_name", "product_description", "category",
            "manufacturer", "expiry_date", "serial_number",
            "sku", "weight", "origin", "price",
        ]
        for k in display_fields:
            if k in matched_row and matched_row[k] is not None:
                # Use mapped name if available
                display_name = column_mappings.get(k, k)
                if display_name not in product_preview:
                    product_preview[display_name] = matched_row[k]

        # Ensure product_id exists (required for OTP claiming)
        if "product_id" not in product_preview:
            for alt_name in ["productid", "id", "product_code", "item_id", "batchid"]:
                if alt_name in matched_row and matched_row[alt_name] is not None:
                    product_preview["product_id"] = matched_row[alt_name]
                    print(f"[DEBUG] Using '{alt_name}' as product_id: {matched_row[alt_name]}")
                    break

        # Ensure batch exists
        if "batch" not in product_preview:
            for alt_name in ["batch_number", "batchid"]:
                if alt_name in matched_row and matched_row[alt_name] is not None:
                    product_preview["batch"] = matched_row[alt_name]
                    print(f"[DEBUG] Using '{alt_name}' as batch: {matched_row[alt_name]}")
                    break

        # If still no product_id, use batch as fallback
        if "product_id" not in product_preview and "batch" in product_preview:
            product_preview["product_id"] = product_preview["batch"]
            print(f"[DEBUG] Using 'batch' as product_id fallback: {product_preview['batch']}")

        if len(product_preview) < 5:
            for k, v in matched_row.items():
                if k not in product_preview and v is not None and not k.startswith("_"):
                    product_preview[k] = v

        print(f"[DEBUG] Final product_preview: {product_preview}")

    return jsonify({
        "status": final_status,
        "verified": verified,
        "reason": reason,
        "product": product_preview,
        "scan_history": scan_history,
    })


@app.route("/api/check_ownership", methods=["POST"])
def check_ownership():
    """
    Check if ownership has been claimed for a token and verify device fingerprint.
    Expected JSON: {"token": "...", "device_fingerprint": "...", "product_id": "...", "batch_id": "..."}
    """
    data = request.get_json()
    token = data.get("token", "")
    device_fingerprint = data.get("device_fingerprint", "")
    product_id = data.get("product_id", "")
    batch_id = data.get("batch_id", "")

    if not token:
        return jsonify({"error": "Token is required"}), 400

    # First try to find ownership by token
    ownership = get_ownership(token)

    # If not found by token, try by product_id or batch_id
    if not ownership and (product_id or batch_id):
        ownership = get_ownership_by_product(product_id, batch_id)

    if not ownership:
        return jsonify({
            "claimed": False,
            "message": "Ownership has not been claimed for this product."
        })

    # Check if device fingerprint matches
    if ownership.get("device_fingerprint") != device_fingerprint:
        return jsonify({
            "claimed": True,
            "authorized": False,
            "message": "This product has been claimed by another device."
        })

    # claimed_at is already a string from CSV, no need to call isoformat()
    claimed_at = ownership.get("claimed_at", "")

    return jsonify({
        "claimed": True,
        "authorized": True,
        "device_make": ownership.get("device_make", "Unknown"),
        "device_model": ownership.get("device_model", "Unknown"),
        "claimed_at": claimed_at,
        "owner_name": ownership.get("owner_name", ""),
        "owner_phone": mask_phone(ownership.get("owner_phone", ""))
    })


@app.route("/api/claim_ownership", methods=["POST"])
def claim_ownership_endpoint():
    """
    Claim ownership of a product by verifying OTP.
    Expected JSON: {
        "token": "...",
        "product_id": "...",
        "batch_id": "...",
        "otp_code": "...",
        "owner_name": "...",
        "owner_phone": "...",
        "device_fingerprint": "...",
        "device_make": "...",
        "device_model": "..."
    }
    """
    data = request.get_json()

    token = data.get("token", "")
    product_id = data.get("product_id", "")
    batch_id = data.get("batch_id", "")
    otp_code = data.get("otp_code", "").strip()
    owner_name = data.get("owner_name", "").strip()
    owner_phone = data.get("owner_phone", "").strip()
    device_fingerprint = data.get("device_fingerprint", "")
    device_make = data.get("device_make", "Unknown")
    device_model = data.get("device_model", "Unknown")

    # Validate inputs - token is required, product_id is optional (can use token for lookup)
    if not all([token, otp_code, owner_name, owner_phone, device_fingerprint]):
        return jsonify({
            "success": False,
            "message": "All fields are required."
        }), 400

    # Check if already claimed
    existing_ownership = get_ownership(token)
    if existing_ownership:
        return jsonify({
            "success": False,
            "message": "This product has already been claimed."
        }), 400

    # Verify OTP - try multiple lookup methods
    correct_otp = get_otp_for_product(product_id=product_id, batch_id=batch_id, token=token)
    if not correct_otp:
        return jsonify({
            "success": False,
            "message": "Unable to verify OTP for this product."
        }), 400

    if correct_otp != otp_code:
        return jsonify({
            "success": False,
            "message": "Invalid OTP code. Please check and try again."
        }), 400

    # Claim ownership
    success, message = claim_ownership(
        token, product_id, batch_id, otp_code,
        owner_name, owner_phone, device_fingerprint,
        device_make, device_model
    )

    if success:
        return jsonify({
            "success": True,
            "message": message,
            "device_make": device_make,
            "device_model": device_model
        })
    else:
        return jsonify({
            "success": False,
            "message": message
        }), 400


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
