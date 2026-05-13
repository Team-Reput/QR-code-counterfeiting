import os
import json
import csv
import base64
import struct
import urllib.parse
from datetime import datetime, date
from typing import Optional, Tuple, Dict, Any, List
import threading

import psycopg2
from psycopg2.extras import RealDictCursor

import qrcode
from PIL import Image, ImageDraw
import cv2
import numpy as np

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

# --------------------------------------------------------------------------
# Image analysis thresholds — tunable via environment variables.
# SCREENSHOT_NOISE_THRESHOLD : std-dev of black-module pixel luminance.
#   Real prints: ~15–40.  Digital screenshots: <5.
# SCREENSHOT_DIFF_THRESHOLD  : mean absolute pixel diff vs. expected QR.
#   Real prints: ~30–80.  Digital screenshots: <8.
# MICRO_PATTERN_MIN_DIFF     : min brightness gain (dot area vs background).
# MICRO_PATTERN_PASS_RATIO   : fraction of dots that must be visible.
# ---------------------------------------------------------------------------
SCREENSHOT_NOISE_THRESHOLD = float(os.getenv("SCREENSHOT_NOISE_THRESHOLD", "8.0"))
SCREENSHOT_DIFF_THRESHOLD  = float(os.getenv("SCREENSHOT_DIFF_THRESHOLD",  "10.0"))
MICRO_PATTERN_MIN_DIFF     = float(os.getenv("MICRO_PATTERN_MIN_DIFF",     "8.0"))   # was 15.0 — real prints survive blur/ink-spread
MICRO_PATTERN_PASS_RATIO   = float(os.getenv("MICRO_PATTERN_PASS_RATIO",   "0.20"))  # was 0.35 — 20% visible dots is sufficient evidence


# =================================================================
#                        JSON ENCODER
# =================================================================
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


def find_row_by_token_csv(token: str) -> Tuple[Optional[Dict[str, Any]], bool]:
    """
    Fast O(n) lookup: check if `token` matches the `signature_token` column
    in otp_codes.csv (written by qr_generator.py).
    Returns (product_dict, True) on match, (None, False) otherwise.
    The returned dict has the same keys as the CSV header so the /verify
    endpoint can build a product_preview from it.
    """
    try:
        with csv_lock:
            if not os.path.exists(OTP_CSV_FILE):
                return None, False
            with open(OTP_CSV_FILE, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    sig_token = row.get('signature_token', '').strip()
                    if sig_token and sig_token == token.strip():
                        # Build a product-like dict from the CSV row
                        product = {k: v for k, v in row.items()
                                   if k not in ('signature_token', 'token',
                                                'owner_name', 'owner_phone',
                                                'device_fingerprint', 'device_make',
                                                'device_model', 'claimed_at',
                                                'otp_code')}
                        return product, True
    except Exception as e:
        print(f"[WARN] find_row_by_token_csv failed: {e}")
    return None, False


def find_row_by_token(token: str) -> Tuple[Optional[Dict[str, Any]], bool]:
    """
    Locate the matching product row for a given signature token.

    Strategy (in order):
      1. Fast CSV lookup  — checks otp_codes.csv `signature_token` column.
         This is the primary path when QR codes are generated by qr_generator.py.
      2. DB brute-force   — verifies Ed25519 signature over every DB row.
         Legacy path for QR codes generated directly from the database.
    """
    # 1. Try CSV first (fast, no DB round-trip)
    row, ok = find_row_by_token_csv(token)
    if ok:
        print(f"[DEBUG] Token matched via CSV lookup (batch_id={row.get('batch_id')})")
        return row, True

    # 2. Fallback: brute-force verify against every DB row
    try:
        rows = fetch_candidate_rows()
        for row in rows:
            data = canonical_product_json(row)
            if verify_ed25519_signature(PUBLIC_KEY, data, token):
                print(f"[DEBUG] Token matched via DB brute-force")
                return row, True
    except Exception as e:
        print(f"[WARN] DB brute-force lookup failed: {e}")

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

    dot_r = max(2, QR_BOX_SIZE // 4)
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


def _contour_crop_qr(img_pil: Image.Image) -> Image.Image:
    """
    Improved alignment fallback (used when OpenCV QR corner detection fails).
    Finds the largest near-square dark region via contour detection and crops
    to it with a small margin.  Much better than a blind min(w,h) square crop
    when the QR occupies only a sub-region of a larger photo.
    Falls back to crop_qr_square if contour detection fails.
    """
    try:
        img_cv = cv2.cvtColor(np.array(img_pil.convert("RGB")), cv2.COLOR_RGB2BGR)
        gray   = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
        _, binary = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)
        cnts, _ = cv2.findContours(binary, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

        best_rect = None
        best_area = 0
        for cnt in cnts:
            x, y, bw, bh = cv2.boundingRect(cnt)
            if bw < 50 or bh < 50:
                continue
            aspect = max(bw, bh) / max(1, min(bw, bh))
            if aspect < 2.0 and bw * bh > best_area:
                best_area = bw * bh
                best_rect = (x, y, bw, bh)

        if best_rect:
            x, y, bw, bh = best_rect
            side   = max(bw, bh)
            margin = max(5, side // 15)
            ih, iw = img_cv.shape[:2]
            x0 = max(0, x - margin)
            y0 = max(0, y - margin)
            x1 = min(iw, x + bw + margin)
            y1 = min(ih, y + bh + margin)
            cropped = img_cv[y0:y1, x0:x1]
            return Image.fromarray(cv2.cvtColor(cropped, cv2.COLOR_BGR2RGB))
    except Exception as e:
        print(f"[WARN] _contour_crop_qr failed: {e}")

    return crop_qr_square(img_pil)


# ================================================================
#           LAYER 2 — LSB WATERMARK DETECTION
#
# qr_generator.py embeds a JSON payload in the LSB of the Red
# channel.  A genuine camera photo of a physical print ALWAYS
# destroys this watermark (ink spread + optical noise).
# A direct digital copy (PNG screenshot) keeps it intact.
# JPEG screenshots may lose it due to compression, so this check
# is used as a *fast-fail* only; the noise classifier handles JPEG.
# ================================================================
def _extract_lsb_watermark(img: Image.Image) -> Optional[Dict[str, Any]]:
    """
    Attempt to extract the LSB steganographic watermark written by qr_generator.py.
    Returns the payload dict when the watermark is intact, None otherwise.
    A non-None return means the image is a digital copy, not a physical label scan.
    """
    try:
        img_rgb = img.convert("RGB")
        pixels  = img_rgb.load()
        w, h    = img_rgb.size
        total   = w * h

        def _read_bits(start: int, n: int) -> List[int]:
            out, idx = [], start
            while len(out) < n and idx < total:
                px, py = idx % w, idx // w
                r, _, _ = pixels[px, py]
                out.append(r & 1)
                idx += 1
            return out

        def _to_int(bits: List[int]) -> int:
            v = 0
            for b in bits:
                v = (v << 1) | b
            return v

        def _to_bytes(bits: List[int]) -> bytes:
            ba = bytearray()
            for i in range(0, len(bits) - 7, 8):
                ba.append(_to_int(bits[i:i + 8]))
            return bytes(ba)

        header_bits = _read_bits(0, 32)
        if len(header_bits) < 32:
            return None
        length = _to_int(header_bits)
        if length <= 0 or length > (total // 8) - 4:
            return None

        payload = _to_bytes(_read_bits(32, length * 8))
        data = json.loads(payload.decode("utf-8"))
        if isinstance(data, dict) and "batch_id" in data:
            return data
    except Exception:
        pass
    return None


# ================================================================
#           LAYER 3a — OPENCV QR ALIGNMENT (MULTI-STRATEGY)
#
# Three progressively aggressive preprocessing strategies are tried
# so that real camera photos at various angles / lighting conditions
# can be accurately perspective-corrected before pattern analysis.
# ================================================================
def _align_qr_image(img_pil: Image.Image) -> Tuple[Image.Image, bool]:
    """
    Locate and perspective-warp the QR code in the image to a perfect square.
    Tries: original → CLAHE-enhanced → Otsu-thresholded → sharpened.
    Returns (aligned_image, cv_detection_succeeded).
    """
    def _detect_corners(img_cv) -> Optional[np.ndarray]:
        detector = cv2.QRCodeDetector()
        try:
            _, _, points, _ = detector.detectAndDecodeMulti(img_cv)
            if points is not None and len(points) > 0:
                return points[0].astype(np.float32)
        except Exception:
            pass
        return None

    def _warp(img_cv, src_pts: np.ndarray) -> Image.Image:
        side = int(max(
            np.linalg.norm(src_pts[0] - src_pts[1]),
            np.linalg.norm(src_pts[1] - src_pts[2]),
        ))
        side = max(side, 200)
        dst = np.array([[0, 0], [side - 1, 0],
                        [side - 1, side - 1], [0, side - 1]], dtype=np.float32)
        M = cv2.getPerspectiveTransform(src_pts, dst)
        warped = cv2.warpPerspective(img_cv, M, (side, side))
        return Image.fromarray(cv2.cvtColor(warped, cv2.COLOR_BGR2RGB))

    try:
        img_cv = cv2.cvtColor(np.array(img_pil.convert("RGB")), cv2.COLOR_RGB2BGR)
        gray   = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)

        # Strategy 1: original image
        pts = _detect_corners(img_cv)
        if pts is not None:
            return _warp(img_cv, pts), True

        # Strategy 2: CLAHE contrast enhancement (helps with poor lighting)
        clahe    = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        enhanced = cv2.cvtColor(clahe.apply(gray), cv2.COLOR_GRAY2BGR)
        pts = _detect_corners(enhanced)
        if pts is not None:
            return _warp(img_cv, pts), True  # warp the original, not the enhanced

        # Strategy 3: Otsu global thresholding (high-contrast binary image)
        _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        pts = _detect_corners(cv2.cvtColor(otsu, cv2.COLOR_GRAY2BGR))
        if pts is not None:
            return _warp(img_cv, pts), True

        # Strategy 4: unsharp-mask sharpening (low-contrast / slightly blurry prints)
        kernel    = np.array([[-1, -1, -1], [-1, 9, -1], [-1, -1, -1]], dtype=np.float32)
        sharpened = cv2.filter2D(img_cv, -1, kernel)
        pts = _detect_corners(sharpened)
        if pts is not None:
            return _warp(img_cv, pts), True  # warp the original, not the sharpened

    except Exception as e:
        print(f"[WARN] QR alignment failed: {e}")

    return img_pil, False


# ================================================================
#           LAYER 3b — IMAGE TYPE CLASSIFIER
#
# Real camera photos of printed labels have two measurable traits
# that digital screenshots lack:
#   1. Camera sensor noise / print texture → black modules are NOT
#      pure black; they show luminance std-dev of 15–40.
#   2. Global pixel difference vs. regenerated expected QR is large
#      (30–80) because of ink spread, paper texture and optics.
# Screenshots have std-dev < 5 and pixel-diff < 8.
# ================================================================
def _classify_image(
    scanned_resized: Image.Image,
    expected_base: Image.Image,
    expected_patterned: Image.Image,
) -> Dict[str, Any]:
    """
    Classify the aligned, resized scanned image as 'screenshot', 'real_photo',
    or 'borderline' using two independent metrics.

    pixel_diff uses min(diff_vs_base, diff_vs_patterned) so that both a plain-QR
    screenshot AND a screenshot of the watermarked generator PNG are caught.
    """
    arr_scan      = np.array(scanned_resized.convert("RGB"),    dtype=np.float32)
    arr_base      = np.array(expected_base.convert("RGB"),      dtype=np.float32)
    arr_patterned = np.array(expected_patterned.convert("RGB"), dtype=np.float32)

    w       = expected_base.width
    modules = w // QR_BOX_SIZE
    margin  = max(1, QR_BOX_SIZE // 4)  # sample interior, away from module edges

    black_lum: List[float] = []

    for my in range(QR_BORDER + 3, modules - QR_BORDER - 3):
        for mx in range(QR_BORDER + 3, modules - QR_BORDER - 3):
            # Skip all three finder pattern areas
            if ((mx < QR_BORDER + 9 and my < QR_BORDER + 9) or
                    (mx >= modules - QR_BORDER - 9 and my < QR_BORDER + 9) or
                    (mx < QR_BORDER + 9 and my >= modules - QR_BORDER - 9)):
                continue

            cx = mx * QR_BOX_SIZE + QR_BOX_SIZE // 2
            cy = my * QR_BOX_SIZE + QR_BOX_SIZE // 2
            er, _, _ = expected_base.getpixel((min(cx, w - 1), min(cy, w - 1)))
            if er > 128:        # only black modules in the clean base image
                continue

            # Four interior corners of this module (avoid center where dot may be)
            for dx, dy in [(-margin, -margin), (margin, -margin),
                           (-margin,  margin), (margin,  margin)]:
                px = min(max(cx + dx, 0), w - 1)
                py = min(max(cy + dy, 0), w - 1)
                r, g, b = scanned_resized.getpixel((px, py))
                black_lum.append((r + g + b) / 3.0)

    module_noise_std = float(np.std(black_lum)) if len(black_lum) >= 10 else 0.0

    # B5: take the minimum diff against both expected variants.
    # A screenshot of the plain QR matches base; a screenshot of the
    # watermarked generator PNG matches patterned — both get caught.
    mean_pixel_diff = float(min(
        np.abs(arr_scan - arr_base).mean(),
        np.abs(arr_scan - arr_patterned).mean(),
    ))

    noise_low = module_noise_std < SCREENSHOT_NOISE_THRESHOLD
    diff_low  = mean_pixel_diff  < SCREENSHOT_DIFF_THRESHOLD

    print(f"[DEBUG] Image classifier: noise_std={module_noise_std:.2f}, "
          f"pixel_diff={mean_pixel_diff:.2f}")

    if noise_low and diff_low:
        img_type = "screenshot"
    elif not noise_low:
        img_type = "real_photo"
    else:
        img_type = "borderline"

    return {
        "image_type":        img_type,
        "module_noise_std":  round(module_noise_std, 2),
        "mean_pixel_diff":   round(mean_pixel_diff,  2),
    }


# ================================================================
#           LAYER 4 — MICRO-PATTERN RELATIVE-BRIGHTNESS CHECK
#
# Instead of an absolute "pixel must be > 200" test (which fails on
# real prints where dots appear grey, not white), we compare the
# luminance at the DOT position against the BACKGROUND of the same
# module (opposite corner).
#
# Genuine label:  dot ≈ 100-180, background ≈ 20-60 → diff ≈ 60-120 ✓
# Counterfeit:    dot ≈ 20-60,  background ≈ 20-60 → diff ≈ 0-10   ✗
# Screenshot:     caught by Layers 2/3 before reaching here.
# ================================================================
def _verify_micro_pattern(
    scanned_resized: Image.Image,
    expected_base: Image.Image,
) -> Tuple[bool, float]:
    """
    Verify micro-pattern dots using relative brightness (dot vs. in-module background).
    Returns (passed, score_percent).
    """
    w, _    = expected_base.size
    modules = w // QR_BOX_SIZE

    dot_r  = max(3, QR_BOX_SIZE // 3)   # wider sample area — was QR_BOX_SIZE//4 (2px), too small to survive print chain
    offset = max(1, QR_BOX_SIZE // 3)   # must match generator offset

    TOP_STRIP_THICKNESS   = 4
    RIGHT_STRIP_THICKNESS = 4
    timing_row = QR_BORDER + 6
    timing_col = QR_BORDER + 6

    top_y_start   = QR_BORDER
    top_y_end     = min(modules - QR_BORDER, QR_BORDER + TOP_STRIP_THICKNESS)
    right_x_start = max(QR_BORDER, modules - QR_BORDER - RIGHT_STRIP_THICKNESS)
    right_x_end   = modules - QR_BORDER

    def _in_quiet(mx: int, my: int) -> bool:
        return (mx < QR_BORDER or my < QR_BORDER or
                mx >= modules - QR_BORDER or my >= modules - QR_BORDER)

    def _in_finder(mx: int, my: int) -> bool:
        if mx < QR_BORDER + 9 and my < QR_BORDER + 9:             return True
        if mx >= modules - QR_BORDER - 9 and my < QR_BORDER + 9:  return True
        if mx < QR_BORDER + 9 and my >= modules - QR_BORDER - 9:  return True
        return False

    def _mean_lum(cx: int, cy: int, r: int) -> float:
        vals: List[float] = []
        for ox in range(-r, r + 1):
            for oy in range(-r, r + 1):
                px = min(max(cx + ox, 0), w - 1)
                py = min(max(cy + oy, 0), w - 1)
                pr, pg, pb = scanned_resized.getpixel((px, py))
                vals.append((pr + pg + pb) / 3.0)
        return float(np.mean(vals)) if vals else 0.0

    checked = dots_visible = 0

    for my in range(QR_BORDER, modules - QR_BORDER):
        for mx in range(QR_BORDER, modules - QR_BORDER):
            if _in_quiet(mx, my) or _in_finder(mx, my):
                continue
            if mx == timing_col or my == timing_row:
                continue

            in_top   = top_y_start   <= my < top_y_end
            in_right = right_x_start <= mx < right_x_end
            if not (in_top or in_right):
                continue

            cx = mx * QR_BOX_SIZE + QR_BOX_SIZE // 2
            cy = my * QR_BOX_SIZE + QR_BOX_SIZE // 2

            er, eg, eb = expected_base.getpixel((min(cx, w - 1), min(cy, w - 1)))
            if er > 128:   # only black modules carry a dot
                continue

            # Expected dot position (matches generator)
            dot_x = cx - offset // 2
            dot_y = cy + offset // 2

            # Reference background — opposite corner of the same module
            bg_x = cx + offset // 2
            bg_y = cy - offset // 2

            dot_lum = _mean_lum(dot_x, dot_y, dot_r)
            bg_lum  = _mean_lum(bg_x,  bg_y,  dot_r)

            checked += 1
            if dot_lum - bg_lum >= MICRO_PATTERN_MIN_DIFF:
                dots_visible += 1

    if checked == 0:
        print("[WARN] Micro-pattern: no checkable dots found (checked=0)")
        return False, 0.0

    score  = 100.0 * dots_visible / checked
    passed = score >= (MICRO_PATTERN_PASS_RATIO * 100)
    print(f"[DEBUG] Micro-pattern: {dots_visible}/{checked} dots, score={score:.1f}%")
    return passed, score


# ================================================================
#           FILE-UPLOAD ORIGINAL-FILE VERIFIER
#
# The file-upload path has ONE acceptance rule:
#   The uploaded file must be the exact original PNG produced by the
#   generator — proven by (a) an intact LSB watermark and (b) near-zero
#   pixel difference against the expected patterned QR image.
#
# Rejects:
#   • JPEG screenshots  — JPEG codec destroys LSB bits
#   • PNG screenshots   — screen-rendering pipeline changes pixels
#   • Camera photos     — optics + sensor noise destroy LSB
#   • Edited copies     — any pixel change raises diff above threshold
# ================================================================
def _verify_original_file(qr_img: Image.Image, url_in: str) -> dict:
    """
    Return {"is_original": True, ...} only when qr_img is the exact
    original PNG generated by qr_generator.py.
    """
    payload_text = url_in.strip()

    # Step 1: LSB watermark must be intact
    wm_data = _extract_lsb_watermark(qr_img)
    if not wm_data:
        return {
            "is_original": False,
            "lsb_intact":  False,
            "reason": (
                "This does not appear to be the original generated QR file. "
                "Screenshots and photos are not accepted — please upload the "
                "original QR PNG file directly."
            ),
        }

    # Step 2: pixel diff vs expected patterned QR must be near-zero
    expected_patterned = apply_micro_pattern_top_and_right(make_qr_image(payload_text))
    # crop_qr_square removes any OTP text strip the generator may have appended
    qr_cropped = crop_qr_square(qr_img)
    scan_arr = np.array(
        qr_cropped.resize(expected_patterned.size, Image.LANCZOS).convert("RGB"),
        dtype=np.float32,
    )
    exp_arr = np.array(expected_patterned.convert("RGB"), dtype=np.float32)
    diff = float(np.abs(scan_arr - exp_arr).mean())

    print(f"[DEBUG] _verify_original_file: lsb_intact=True, diff_vs_patterned={diff:.2f}")

    if diff < SCREENSHOT_DIFF_THRESHOLD:
        return {"is_original": True, "lsb_intact": True, "diff": round(diff, 2)}

    return {
        "is_original": False,
        "lsb_intact":  True,
        "reason": (
            f"File content does not match the expected QR pattern "
            f"(diff={diff:.1f}). Please upload the unmodified original QR PNG file."
        ),
    }


# ================================================================
#           LAYER 3c — CANONICAL GRID NORMALISER
#
# After perspective warp, OpenCV crops to the finder-pattern corners,
# so the warped image has no quiet zone.  After a blind square-crop the
# QR may be a small sub-region of a larger photo.  In both cases the
# module positions assumed by the pattern checker (mx*BOX_SIZE pixels
# from the top-left) are wrong.
#
# _normalize_to_qr_grid detects the actual dark-content bounding box,
# expands it by an estimated quiet-zone margin, and re-sizes so that
# module (QR_BORDER, QR_BORDER) lands at the expected pixel coordinate.
# ================================================================
def _normalize_to_qr_grid(aligned: Image.Image, canonical_size: int) -> Image.Image:
    """
    Re-crop the aligned image to include QR content + estimated quiet zone,
    then resize to canonical_size × canonical_size.
    Falls back to a plain resize when the heuristic cannot locate the QR.
    """
    arr = np.array(aligned.convert("L"), dtype=np.uint8)
    h, w = arr.shape
    min_count = max(1, int(min(h, w) * 0.05))

    row_dark = (arr < 128).sum(axis=1) >= min_count
    col_dark = (arr < 128).sum(axis=0) >= min_count

    if not row_dark.any() or not col_dark.any():
        return aligned.resize((canonical_size, canonical_size), Image.LANCZOS)

    r_min = int(np.where(row_dark)[0][0])
    r_max = int(np.where(row_dark)[0][-1])
    c_min = int(np.where(col_dark)[0][0])
    c_max = int(np.where(col_dark)[0][-1])

    content_h = r_max - r_min
    content_w = c_max - c_min

    # Sanity: content must be roughly square and cover >10 % of the image
    if content_h < h * 0.1 or content_w < w * 0.1:
        return aligned.resize((canonical_size, canonical_size), Image.LANCZOS)
    if max(content_h, content_w) / max(1, min(content_h, content_w)) > 2.5:
        return aligned.resize((canonical_size, canonical_size), Image.LANCZOS)

    total_modules = canonical_size // QR_BOX_SIZE
    data_modules  = max(1, total_modules - 2 * QR_BORDER)
    est_ppm       = (content_h + content_w) / (2.0 * data_modules)
    quiet_px      = max(2, int(round(QR_BORDER * est_ppm)))

    x0 = max(0, c_min - quiet_px)
    y0 = max(0, r_min - quiet_px)
    x1 = min(w, c_max + quiet_px)
    y1 = min(h, r_max + quiet_px)

    cropped = aligned.crop((x0, y0, x1, y1))
    return cropped.resize((canonical_size, canonical_size), Image.LANCZOS)


# ================================================================
#           COMBINED IMAGE VERIFICATION PIPELINE
# ================================================================
def _run_image_verification(
    qr_img: Image.Image,
    url_in: str,
) -> Dict[str, Any]:
    """
    Execute all four physical-verification layers on the uploaded image.
    Returns a result dict with keys:
      image_type, lsb_intact, cv_aligned, module_noise_std,
      mean_pixel_diff, pattern_score, micro_ok
    """
    result: Dict[str, Any] = {
        "image_type":       "unknown",
        "lsb_intact":       False,
        "cv_aligned":       False,
        "module_noise_std": 0.0,
        "mean_pixel_diff":  0.0,
        "pattern_score":    0.0,
        "micro_ok":         False,
    }

    payload_text = url_in.strip()

    # Layer 2: LSB watermark check on the raw upload (before any resampling).
    # An intact watermark alone does NOT auto-fail: the original generator PNG
    # also has an intact watermark.  We only call it a screenshot when the
    # watermark is intact AND the pixel-diff vs. the expected QR is near-zero
    # (i.e. the file is a pristine digital copy, not a camera photo of a print).
    wm_data = _extract_lsb_watermark(qr_img)
    result["lsb_intact"] = wm_data is not None
    if wm_data:
        print(f"[DEBUG] LSB watermark intact: {wm_data} — checking pixel diff before classifying")
        # Build expected to measure pixel-diff
        _exp_tmp = make_qr_image(payload_text)
        _exp_arr = np.array(_exp_tmp.convert("RGB"), dtype=np.float32)
        _scan_arr = np.array(
            qr_img.resize(_exp_tmp.size, Image.LANCZOS).convert("RGB"), dtype=np.float32
        )
        _diff = float(np.abs(_scan_arr - _exp_arr).mean())
        print(f"[DEBUG] LSB intact pixel-diff={_diff:.2f}")
        if _diff < SCREENSHOT_DIFF_THRESHOLD:  # near-zero diff → digital copy
            result["image_type"] = "screenshot"
            return result
        # Large diff → physical print that still carries readable watermark bits
        # (uncommon but possible with low-noise printers); continue to pattern check.
        print("[DEBUG] LSB intact but large pixel-diff → treating as physical print")

    # Build expected QR images (shared by classifier and pattern checker)
    expected_base      = make_qr_image(payload_text)
    expected_patterned = apply_micro_pattern_top_and_right(expected_base.copy())

    # Layer 3a: Align the uploaded image
    aligned, cv_ok = _align_qr_image(qr_img)
    result["cv_aligned"] = cv_ok
    if not cv_ok:
        aligned = _contour_crop_qr(qr_img)  # B4: smarter than crop_qr_square for sub-region photos

    # B3: re-crop to canonical grid so module pixel positions are correct
    scanned_resized = _normalize_to_qr_grid(aligned, expected_patterned.size[0])

    # Layer 3b: Classify image type
    classification = _classify_image(scanned_resized, expected_base, expected_patterned)
    result.update(classification)

    if result["image_type"] == "screenshot":
        return result

    # Layer 4: Micro-pattern relative-brightness check
    micro_ok, score = _verify_micro_pattern(scanned_resized, expected_base)
    result["micro_ok"]      = micro_ok
    result["pattern_score"] = round(score, 1)
    return result


# ================================================================
#                    COUNTRY DETECTION (GPS)
# ================================================================
GEO_USER_AGENT = os.getenv(
    "GEO_USER_AGENT",
    "ReputQRVerification/1.0 (admin@reput.co.in)",
)


def detect_country(lat, lng):
    if lat is None or lng is None:
        print("[GEO] lat/lng not provided — country Unknown")
        return "Unknown"
    try:
        geolocator = Nominatim(user_agent=GEO_USER_AGENT)
        location = geolocator.reverse((lat, lng), language="en", timeout=5)
        if not location:
            print(f"[GEO] reverse geocode returned nothing for ({lat}, {lng})")
            return "Unknown"
        country = location.raw.get("address", {}).get("country", "Unknown")
        print(f"[GEO] ({lat}, {lng}) → {country}")
        return country
    except Exception as e:
        print(f"[GEO] detect_country error: {e}")
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

            # Safeguard: if fieldnames is empty (due to race condition file wipe), restore base
            if not fieldnames:
                fieldnames = ['batch_id', 'signature_token', 'otp_code']

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

            # Write back all rows atomically using a temp file
            import tempfile
            temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(OTP_CSV_FILE), prefix="otp_tmp_", suffix=".csv")
            try:
                with os.fdopen(temp_fd, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(rows)
                    f.flush()
                    os.fsync(f.fileno())
                # Atomic replace
                os.replace(temp_path, OTP_CSV_FILE)
            except Exception as e:
                # Cleanup temp file on error
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                raise e

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


@app.route("/api/admin/clear_scan_history", methods=["POST"])
def clear_scan_history():
    """
    Delete scan log rows for a specific token (or all rows when token='*').
    Body JSON: { "token": "<token>" }  — pass token='*' to wipe all rows.
    Protected by a simple admin key (env ADMIN_KEY; defaults to 'reput-admin').
    """
    ADMIN_KEY = os.getenv("ADMIN_KEY", "reput-admin")
    provided_key = request.headers.get("X-Admin-Key", "")
    if provided_key != ADMIN_KEY:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json(silent=True) or {}
    token = data.get("token", "").strip()
    if not token:
        return jsonify({"error": "token is required"}), 400

    try:
        conn = db_connect()
        try:
            with conn.cursor() as cur:
                if token == "*":
                    cur.execute(f"DELETE FROM {SCAN_LOG_TABLE}")
                else:
                    cur.execute(
                        f"DELETE FROM {SCAN_LOG_TABLE} WHERE token = %s",
                        (token,),
                    )
                deleted = cur.rowcount
            conn.commit()
        finally:
            conn.close()
        print(f"[ADMIN] clear_scan_history token={token!r} deleted={deleted}")
        return jsonify({"deleted": deleted})
    except Exception as e:
        print(f"[ADMIN] clear_scan_history error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/results")
def results():
    return render_template("results.html")


# ================================================================
#   QR DECODE HELPER  —  shared by /api/decode_qr and _opencv_decode_url
#
#   Five preprocessing strategies are tried in order so that real camera
#   photos of printed labels are decoded as reliably as digital images:
#     1. Raw frame
#     2. CLAHE contrast enhancement   (poor / uneven lighting)
#     3. Otsu global threshold         (low contrast)
#     4. Unsharp-mask sharpening       (slightly blurry prints)
#     5. 2× bicubic upscale            (small / distant QR codes)
# ================================================================
def _try_decode_url_from_cv(img_cv) -> Optional[str]:
    """
    Attempt to decode a QR URL from an OpenCV BGR image.
    Returns the first non-empty decoded string, or None.
    """
    detector = cv2.QRCodeDetector()

    def _decode(frame) -> Optional[str]:
        try:
            retval, decoded_info, _, _ = detector.detectAndDecodeMulti(frame)
            if retval and decoded_info:
                for text in decoded_info:
                    if text and text.strip():
                        return text.strip()
        except Exception:
            pass
        return None

    # Strategy 1: raw
    result = _decode(img_cv)
    if result:
        return result

    gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)

    # Strategy 2: CLAHE contrast enhancement
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    result = _decode(cv2.cvtColor(clahe.apply(gray), cv2.COLOR_GRAY2BGR))
    if result:
        return result

    # Strategy 3: Otsu global threshold
    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    result = _decode(cv2.cvtColor(otsu, cv2.COLOR_GRAY2BGR))
    if result:
        return result

    # Strategy 4: unsharp-mask sharpening (enhances low-contrast finder patterns)
    kernel    = np.array([[-1, -1, -1], [-1, 9, -1], [-1, -1, -1]], dtype=np.float32)
    sharpened = cv2.filter2D(img_cv, -1, kernel)
    result = _decode(sharpened)
    if result:
        return result

    # Strategy 5: 2× upscale (helps small or distant QR codes)
    h, w = img_cv.shape[:2]
    up2  = cv2.resize(img_cv, (w * 2, h * 2), interpolation=cv2.INTER_CUBIC)
    result = _decode(up2)
    if result:
        return result

    return None


# ================================================================
#   /api/decode_qr  —  OpenCV-powered QR decoding endpoint
#
#   The web frontend streams compressed JPEG frames here instead of
#   running jsQR locally.  OpenCV decodes the payload and returns the
#   full URL string so the frontend can then call /verify with both
#   the URL and a high-resolution image for micro-pattern analysis.
#
#   Input  (multipart/form-data):
#     frame  — JPEG or PNG image blob captured from the <video> element
#
#   Output (JSON):
#     { "decoded": true,  "url": "https://..." }   on success
#     { "decoded": false, "url": null }             when no QR found
#     { "decoded": false, "error": "..." }          on exception
# ================================================================
@app.route("/api/decode_qr", methods=["POST"])
def decode_qr():
    """
    Lightweight, fast endpoint: accepts a compressed video frame from
    the browser and uses OpenCV to locate and decode the QR code.
    No cryptographic or micro-pattern work is done here — this is
    purely a QR text extraction step.
    """
    frame_file = request.files.get("frame")
    if not frame_file:
        return jsonify({"decoded": False, "url": None, "error": "No frame provided"}), 400

    try:
        file_bytes = np.frombuffer(frame_file.read(), dtype=np.uint8)
        img_cv     = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)

        if img_cv is None:
            return jsonify({"decoded": False, "url": None, "error": "Could not decode image"}), 400

        url_found = _try_decode_url_from_cv(img_cv)
        if url_found:
            print(f"[DEBUG] /api/decode_qr — decoded: {url_found[:80]}...")
            return jsonify({"decoded": True, "url": url_found})

        return jsonify({"decoded": False, "url": None})

    except Exception as e:
        print(f"[WARN] /api/decode_qr error: {e}")
        return jsonify({"decoded": False, "url": None, "error": str(e)}), 500


def _opencv_decode_url(qr_file) -> Optional[str]:
    """
    Helper used by /verify: if the client did not supply a 'url' field,
    attempt to extract it from the uploaded qr_image using OpenCV.
    Returns the decoded URL string or None.
    """
    try:
        file_bytes = np.frombuffer(qr_file.read(), dtype=np.uint8)
        qr_file.seek(0)  # rewind so PIL can read it again later
        img_cv = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
        if img_cv is None:
            return None
        return _try_decode_url_from_cv(img_cv)
    except Exception as e:
        print(f"[WARN] _opencv_decode_url failed: {e}")
    return None


@app.route("/verify", methods=["POST"])
def verify_qr():
    """
    Expected inputs (form-data):
      - url   — full scanned URL containing token=... (may be omitted;
                backend will attempt to extract it via OpenCV in that case)
      - qr_image (recommended for micro-pattern)
      - lat, lng (optional, for scan logging only)
    """
    url_in      = request.form.get("url") or ""
    token_in    = request.form.get("token") or ""
    # 'file'   → user uploaded the original generated PNG via the file-input
    # 'camera' → image came from the live video-stream scanner (default)
    scan_source = request.form.get("scan_source", "camera")

    # OpenCV fallback: decode the URL from the image if not supplied by client
    if not url_in:
        qr_file_for_decode = request.files.get("qr_image")
        if qr_file_for_decode:
            url_in = _opencv_decode_url(qr_file_for_decode) or ""
            if url_in:
                print(f"[DEBUG] URL extracted via OpenCV fallback: {url_in[:80]}")
    token = extract_token(token_in) or extract_token(url_in)

    if not token:
        return jsonify({
            "status":       "FAKE",
            "verified":     False,
            "reason":       "Missing or invalid verification token. This QR code cannot be authenticated.",
            "product":      {},
            "scan_history": {"scan_count": 0, "recent_scans": []},
            "checks":       {},
        }), 400

    # ── Layer 1: cryptographic token ──────────────────────────
    matched_row, signature_ok = find_row_by_token(token)

    image_checks: Dict[str, Any] = {}
    verified     = False
    final_status = "FAKE"

    if not signature_ok:
        reason = ("The cryptographic signature on this QR code is invalid. "
                  "This product could not be matched to any authenticated "
                  "record in our system. It may be counterfeit.")

    else:
        qr_file = request.files.get("qr_image")

        if qr_file and url_in and "://" in url_in:
            try:
                qr_img = Image.open(qr_file).convert("RGB")

                # ── FILE-UPLOAD PATH ──────────────────────────────────────
                # Only the exact original generated PNG is accepted.
                # Screenshots and camera photos are rejected here.
                if scan_source == "file":
                    orig = _verify_original_file(qr_img, url_in)
                    image_checks = {
                        "image_type":        "original_file" if orig["is_original"] else "not_original",
                        "lsb_intact":        orig.get("lsb_intact", False),
                        "cv_aligned":        None,
                        "module_noise_std":  None,
                        "mean_pixel_diff":   orig.get("diff"),
                        "pattern_score":     None,
                        "micro_ok":          None,
                    }
                    if orig["is_original"]:
                        final_status = "AUTHENTIC"
                        verified     = True
                        reason       = ("Original generated QR file verified. "
                                        "Cryptographic signature is valid.")
                    else:
                        reason = orig["reason"]

                # ── CAMERA-SCAN PATH ──────────────────────────────────────
                # Physical printed labels pass through micro-pattern analysis.
                # Digital copies (screenshots, phone-screen photos) are rejected.
                else:
                    image_checks = _run_image_verification(qr_img, url_in)
                    img_type     = image_checks.get("image_type", "unknown")

                    if img_type == "screenshot":
                        reason = ("A digital copy of the QR code was detected. "
                                  "Please scan the physical printed label on the "
                                  "product to verify authenticity.")

                    elif not image_checks.get("micro_ok", False):
                        score = image_checks.get("pattern_score", 0.0)
                        if img_type == "borderline" and score >= 30.0:
                            reason = ("Image quality was insufficient for full micro-pattern "
                                      "analysis. Please scan the label in better lighting "
                                      "and try again.")
                        else:
                            reason = ("The cryptographic signature is valid, but the physical "
                                      "security micro-pattern on the QR code was not detected. "
                                      "The printed label may be a counterfeit reproduction.")
                    else:
                        final_status = "AUTHENTIC"
                        verified     = True
                        reason       = ("This product has been verified as authentic. "
                                        "Cryptographic signature and physical security "
                                        "pattern both passed successfully.")

            except Exception as e:
                print(f"[WARN] Image verification error: {e}")
                image_checks = {"image_type": "error", "micro_ok": False}
                reason       = "Image verification failed. Please try again."

        else:
            # Token-only verification (no image uploaded)
            final_status = "AUTHENTIC"
            verified     = True
            reason       = ("Cryptographic signature verified. Upload the original QR file "
                            "or scan the physical label for complete verification.")

    # ── Scan metadata (logging only, not used in decision) ────
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
        "status":       final_status,
        "verified":     verified,
        "reason":       reason,
        "product":      product_preview,
        "scan_history": scan_history,
        "checks": {
            "signature":        signature_ok,
            "image_type":       image_checks.get("image_type"),
            "lsb_watermark":    image_checks.get("lsb_intact"),
            "cv_aligned":       image_checks.get("cv_aligned"),
            "module_noise_std": image_checks.get("module_noise_std"),
            "mean_pixel_diff":  image_checks.get("mean_pixel_diff"),
            "pattern_score":    image_checks.get("pattern_score"),
            "micro_pattern_ok": image_checks.get("micro_ok"),
        },
    })


# OWNERSHIP_DISABLED — uncomment @app.route to re-enable
# @app.route("/api/check_ownership", methods=["POST"])
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


# OWNERSHIP_DISABLED — uncomment @app.route to re-enable
# @app.route("/api/claim_ownership", methods=["POST"])
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
