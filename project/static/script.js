// ===== Backend Config =====
const BACKEND_BASE = window.location.origin || "";

// ===== Global Variables =====
let videoStream = null;
let scanningInterval = null;
let cachedFingerprint = null;

// ===== DOM Elements =====
const fileInput = document.getElementById('fileInput');
const previewImage = document.getElementById('previewImage');
const video = document.getElementById('video');
const scanOverlay = document.getElementById('scanOverlay');
const cameraPrompt = document.getElementById('cameraPrompt');

// -------------------------------------------------------------
// Helpers
// -------------------------------------------------------------
function extractTokenFromUrlText(decodedText) {
  if (!decodedText) return null;
  try {
    const u = new URL(String(decodedText).trim());
    return u.searchParams.get("token");
  } catch (e) {
    return null;
  }
}

function getGeo() {
  return new Promise((resolve) => {
    if (!navigator.geolocation) return resolve({ lat: null, lng: null });

    navigator.geolocation.getCurrentPosition(
      (pos) => resolve({ lat: String(pos.coords.latitude), lng: String(pos.coords.longitude) }),
      () => resolve({ lat: null, lng: null }),
      { enableHighAccuracy: true, timeout: 8000 }
    );
  });
}

async function getDeviceInfo() {
  let make = "Unknown";
  let model = "Unknown";

  // 1. Try User-Agent Client Hints API (Chromium browsers)
  if (navigator.userAgentData && navigator.userAgentData.getHighEntropyValues) {
    try {
      const hints = await navigator.userAgentData.getHighEntropyValues([
        "model", "platform", "platformVersion", "fullVersionList"
      ]);
      if (hints.platform) make = hints.platform;         // e.g. "Android", "Windows"
      if (hints.model) model = hints.model;            // e.g. "SM-S911B", "Pixel 8"
      if (make !== "Unknown" && model && model !== "") {
        return { device_make: make, device_model: model };
      }
    } catch (e) { /* fall through to UA parsing */ }
  }

  // 2. Fallback: parse User-Agent string
  const ua = navigator.userAgent || "";

  // Android devices — UA typically contains "; <Model> Build/"
  const androidModel = ua.match(/;\s*([^;)]+?)\s*(?:Build|MIUI)/i);
  if (androidModel) {
    make = "Android";
    model = androidModel[1].trim();
    // Try to extract brand from model string (first word)
    const knownBrands = ["Samsung", "Xiaomi", "Redmi", "POCO", "OnePlus", "Oppo",
      "Vivo", "Realme", "Huawei", "Honor", "Google", "Pixel", "Motorola",
      "Nokia", "Sony", "LG", "Asus", "Nothing", "Tecno", "Infinix", "Itel"];
    for (const brand of knownBrands) {
      if (model.toUpperCase().startsWith(brand.toUpperCase())) {
        make = brand;
        break;
      }
    }
    return { device_make: make, device_model: model };
  }

  // iPhone / iPad
  if (/iPhone/i.test(ua)) {
    return { device_make: "Apple", device_model: "iPhone" };
  }
  if (/iPad/i.test(ua)) {
    return { device_make: "Apple", device_model: "iPad" };
  }

  // Desktop fallback
  if (/Macintosh/i.test(ua)) return { device_make: "Apple", device_model: "Mac" };
  if (/Windows/i.test(ua)) return { device_make: "Microsoft", device_model: "Windows PC" };
  if (/Linux/i.test(ua)) return { device_make: "Linux", device_model: "Desktop" };
  if (/CrOS/i.test(ua)) return { device_make: "Google", device_model: "Chromebook" };

  return { device_make: make, device_model: model };
}

async function getDeviceFingerprint() {
  if (cachedFingerprint) return cachedFingerprint;
  const parts = [];

  // Screen
  parts.push(screen.width + 'x' + screen.height);
  parts.push(screen.colorDepth);
  parts.push(window.devicePixelRatio || 1);

  // Platform + language
  parts.push(navigator.platform || '');
  parts.push(navigator.language || '');
  parts.push(navigator.hardwareConcurrency || '');

  // Canvas fingerprint
  // try {
  //   const c = document.createElement('canvas');
  //   c.width = 200; c.height = 50;
  //   const ctx = c.getContext('2d');
  //   ctx.textBaseline = 'top';
  //   ctx.font = '14px Arial';
  //   ctx.fillStyle = '#f60';
  //   ctx.fillRect(10, 0, 100, 30);
  //   ctx.fillStyle = '#069';
  //   ctx.fillText('fingerprint', 2, 15);
  //   parts.push(c.toDataURL());
  // } catch (e) { parts.push('no-canvas'); }

  // // WebGL renderer
  // try {
  //   const gl = document.createElement('canvas').getContext('webgl');
  //   if (gl) {
  //     const dbg = gl.getExtension('WEBGL_debug_renderer_info');
  //     if (dbg) parts.push(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL));
  //   }
  // } catch (e) { parts.push('no-webgl'); }

  // Hash it — use WebCrypto (HTTPS/localhost) or fallback djb2 (plain HTTP)
  const raw = parts.join('|');
  if (window.isSecureContext && crypto && crypto.subtle) {
    // Secure context: use SHA-256 via WebCrypto API
    const msgBuf = new TextEncoder().encode(raw);
    const hashBuf = await crypto.subtle.digest('SHA-256', msgBuf);
    const hashArr = Array.from(new Uint8Array(hashBuf));
    cachedFingerprint = hashArr.map(b => b.toString(16).padStart(2, '0')).join('');
  } else {
    // Non-secure context (plain HTTP LAN): pure-JS djb2 hash fallback
    let h = 5381;
    for (let i = 0; i < raw.length; i++) {
      h = ((h << 5) + h) ^ raw.charCodeAt(i);
      h = h >>> 0; // keep unsigned 32-bit
    }
    // Pad to 64 hex chars to match SHA-256 length appearance
    cachedFingerprint = h.toString(16).padStart(8, '0').repeat(8);
  }
  return cachedFingerprint;
}

async function verifyWithBackend(decodedUrl, qrFileOrBlob) {
  const formData = new FormData();

  formData.append("url", decodedUrl);

  const token = extractTokenFromUrlText(decodedUrl);
  if (token) formData.append("token", token);

  const { lat, lng } = await getGeo();
  if (lat && lng) {
    formData.append("lat", lat);
    formData.append("lng", lng);
  }

  const { device_make, device_model } = await getDeviceInfo();
  formData.append("device_make", device_make);
  formData.append("device_model", device_model);

  const fingerprint = await getDeviceFingerprint();
  formData.append("device_fingerprint", fingerprint);

  if (qrFileOrBlob) {
    if (qrFileOrBlob instanceof File) {
      formData.append("qr_image", qrFileOrBlob, qrFileOrBlob.name);
    } else {
      formData.append("qr_image", qrFileOrBlob, "captured_qr.png");
    }
  }

  const res = await fetch(`${BACKEND_BASE}/verify`, {
    method: "POST",
    body: formData
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    // Even on HTTP error, return the data so we can redirect to results
    if (data && data.status) return data;
    return {
      status: "FAKE",
      verified: false,
      reason: "Verification request failed. The server could not process this QR code.",
      product: {}
    };
  }

  return data;
}

// -------------------------------------------------------------
// Navigate to results page
// -------------------------------------------------------------
function goToResults(data, scannedUrl = '') {
  localStorage.setItem('verificationResult', JSON.stringify(data));
  localStorage.setItem('verificationResultTs', Date.now());

  // Extract and store token for ownership claiming
  if (scannedUrl) {
    const token = extractTokenFromUrlText(scannedUrl);
    if (token) {
      localStorage.setItem('currentToken', token);
    }
  }

  window.location.href = '/results';
}

// -------------------------------------------------------------
// Camera
// -------------------------------------------------------------
async function startCamera() {
  const promptBtn = cameraPrompt.querySelector('.btn-allow');
  const promptMsg = cameraPrompt.querySelector('p');

  // ── Secure-context guard ─────────────────────────────────────
  // navigator.mediaDevices is undefined on plain HTTP over a LAN/network IP
  // (e.g. http://192.168.x.x). Camera access requires HTTPS or localhost.
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    const isHttp  = window.location.protocol === 'http:';
    const isLocal = ['localhost', '127.0.0.1'].includes(window.location.hostname);

    let msg = 'Camera requires a secure connection (HTTPS).';
    if (isHttp && !isLocal) {
      msg = `Camera blocked: open this page via localhost instead.\n` +
            `Try: http://localhost:${window.location.port || 5000}/ or http://127.0.0.1:${window.location.port || 5000}/`;
    }

    if (promptMsg) promptMsg.textContent = msg;
    if (promptBtn) { promptBtn.textContent = 'Open Localhost'; promptBtn.onclick = () => {
      window.location.href = `http://localhost:${window.location.port || 5000}/`;
    }; }
    cameraPrompt.classList.remove('hidden');
    console.error('[camera] navigator.mediaDevices unavailable — not a secure context:', window.location.href);
    return;
  }

  // Show a loading state while requesting camera
  if (promptBtn) promptBtn.textContent = 'Starting…';
  if (promptMsg) promptMsg.textContent  = 'Requesting camera access…';
  cameraPrompt.classList.remove('hidden');
  scanOverlay.classList.add('hidden');
  previewImage.classList.add('hidden');

  // Three-tier fallback so the camera works on phones (rear),
  // laptops (front/any) and anything in between.
  const strategies = [
    { video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 1280 } } },
    { video: { width: { ideal: 1280 }, height: { ideal: 1280 } } },
    { video: true },
  ];

  let lastError = null;
  for (const constraints of strategies) {
    try {
      videoStream = await navigator.mediaDevices.getUserMedia(constraints);
      break;
    } catch (err) {
      lastError = err;
      console.warn('[camera] Strategy failed, trying next:', err.name, err.message);
    }
  }

  if (!videoStream) {
    console.error('[camera] All strategies failed:', lastError);
    const reason = lastError
      ? (lastError.name === 'NotAllowedError'
          ? 'Camera permission was denied. Please allow camera access in your browser settings and try again.'
          : lastError.name === 'NotFoundError'
            ? 'No camera found on this device. Please use the Upload QR Image button instead.'
            : `Camera error: ${lastError.message}`)
      : 'Unknown camera error.';

    if (promptMsg) promptMsg.textContent = reason;
    if (promptBtn) promptBtn.textContent = 'Retry';
    cameraPrompt.classList.remove('hidden');
    scanOverlay.classList.add('hidden');
    return;
  }

  // Camera obtained — hide prompt and start streaming
  cameraPrompt.classList.add('hidden');
  scanOverlay.classList.remove('hidden');

  video.srcObject = videoStream;
  video.addEventListener('loadedmetadata', () => {
    startScanning();
  }, { once: true });
}

function stopCamera() {
  if (videoStream) {
    videoStream.getTracks().forEach(track => track.stop());
    videoStream = null;
  }
  if (scanningInterval) {
    clearInterval(scanningInterval);
    scanningInterval = null;
  }
}

// ---------------------------------------------------------------
// startScanning  — OpenCV frame-streaming approach
//
// Instead of running jsQR in the browser, we send compressed JPEG
// frames to the Python backend's /api/decode_qr endpoint.  OpenCV
// on the server decodes the QR text using three strategies (raw →
// CLAHE → Otsu). Once a URL is returned we immediately capture a
// full-resolution, uncompressed PNG and send it to /verify so the
// backend can run the complete counterfeit-detection pipeline
// (micro-pattern, LSB watermark, image classifier, etc.) without
// any browser-side compression artefacts.
// ---------------------------------------------------------------
let _scanBusy = false;   // prevent overlapping requests

function startScanning() {
  const canvas     = document.createElement('canvas');
  const context    = canvas.getContext('2d');
  const hiResCanvas = document.createElement('canvas');
  const hiResCtx   = hiResCanvas.getContext('2d');

  scanningInterval = setInterval(async () => {
    // Skip this tick if a request is still in flight
    if (_scanBusy || video.readyState !== video.HAVE_ENOUGH_DATA) return;
    _scanBusy = true;

    try {
      // ── Step 1: capture a small JPEG frame (low bandwidth) ──────
      const W = video.videoWidth;
      const H = video.videoHeight;
      canvas.width  = W;
      canvas.height = H;
      context.drawImage(video, 0, 0, W, H);

      const jpegBlob = await new Promise(resolve =>
        canvas.toBlob(resolve, 'image/jpeg', 0.55)   // ~55 % quality to save data
      );

      // ── Step 2: send frame to backend OpenCV decoder ─────────────
      const fd = new FormData();
      fd.append('frame', jpegBlob, 'frame.jpg');

      let decodeResp;
      try {
        decodeResp = await fetch(`${BACKEND_BASE}/api/decode_qr`, {
          method: 'POST',
          body: fd
        });
      } catch (networkErr) {
        console.warn('[scan] Network error on /api/decode_qr:', networkErr);
        return;   // try next tick
      }

      const decodeData = await decodeResp.json().catch(() => ({}));

      if (!decodeData.decoded || !decodeData.url) {
        return;   // QR not found yet — keep scanning
      }

      // ── QR code found — stop live scanning ───────────────────────
      stopCamera();
      const decodedUrl = decodeData.url;
      const token      = extractTokenFromUrlText(decodedUrl);

      if (!token) {
        goToResults({
          status:   'FAKE',
          verified: false,
          reason:   'QR code was detected but does not contain a valid verification token. This is not an authenticated product QR code.',
          product:  {}
        });
        return;
      }

      // ── Step 3: capture a HIGH-QUALITY PNG for counterfeit analysis
      //    (uncompressed so micro-pattern dots and LSB bits survive)  ──
      hiResCanvas.width  = W;
      hiResCanvas.height = H;
      hiResCtx.drawImage(video, 0, 0, W, H);   // note: video is stopped but last frame is still accessible

      const hiResBlob = await new Promise(resolve =>
        hiResCanvas.toBlob(resolve, 'image/png')   // lossless
      );

      // ── Step 4: send to /verify for full counterfeit analysis ─────
      try {
        const resp = await verifyWithBackend(decodedUrl, hiResBlob);
        goToResults(resp, decodedUrl);
      } catch (err) {
        goToResults({
          status:   'FAKE',
          verified: false,
          reason:   err.message || 'Server verification failed. Please try again.',
          product:  {}
        });
      }

    } finally {
      _scanBusy = false;
    }
  }, 350);   // poll every 350 ms — fast enough to feel responsive
}

// -------------------------------------------------------------
// File Upload Handling
// (jsQR removed — OpenCV on the backend decodes the QR text)
// -------------------------------------------------------------
fileInput.addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (file) handleFile(file);
});

function handleFile(file) {
  stopCamera();

  const reader = new FileReader();
  reader.onload = (e) => {
    previewImage.src = e.target.result;
    previewImage.classList.remove('hidden');
    scanOverlay.classList.add('hidden');

    decodeQRFromImage(file);
  };
  reader.readAsDataURL(file);
}

// decodeQRFromImage — sends the uploaded file to /api/decode_qr
// so OpenCV extracts the URL, then passes both to /verify.
// (Previously this function used jsQR; jsQR is no longer needed.)
async function decodeQRFromImage(originalFile) {
  try {
    // Step 1: ask OpenCV backend to decode the QR text
    const fd = new FormData();
    fd.append('frame', originalFile, originalFile.name || 'upload.png');

    const decodeResp = await fetch(`${BACKEND_BASE}/api/decode_qr`, {
      method: 'POST',
      body:   fd
    });
    const decodeData = await decodeResp.json().catch(() => ({}));

    if (!decodeData.decoded || !decodeData.url) {
      goToResults({
        status:   'FAKE',
        verified: false,
        reason:   'No QR code could be detected in the uploaded image. Please upload a clear image of the product\'s QR code.',
        product:  {}
      });
      return;
    }

    const decodedUrl = decodeData.url;
    const token      = extractTokenFromUrlText(decodedUrl);

    if (!token) {
      goToResults({
        status:   'FAKE',
        verified: false,
        reason:   'QR code was detected but does not contain a valid verification token. This is not an authenticated product QR code.',
        product:  {}
      });
      return;
    }

    // Step 2: send original file (lossless PNG or high-res JPEG from device)
    // to /verify for the full security pipeline
    const resp = await verifyWithBackend(decodedUrl, originalFile);
    goToResults(resp, decodedUrl);

  } catch (err) {
    goToResults({
      status:   'FAKE',
      verified: false,
      reason:   err.message || 'Server verification failed. Please try again.',
      product:  {}
    });
  }
}

// ===== Initialize =====
document.addEventListener('DOMContentLoaded', () => {
  document.documentElement.style.scrollBehavior = 'smooth';
  startCamera();
});

window.addEventListener('beforeunload', () => {
  stopCamera();
});
