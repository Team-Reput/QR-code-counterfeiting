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
      if (hints.model)    model = hints.model;            // e.g. "SM-S911B", "Pixel 8"
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
  if (/Macintosh/i.test(ua))   return { device_make: "Apple", device_model: "Mac" };
  if (/Windows/i.test(ua))     return { device_make: "Microsoft", device_model: "Windows PC" };
  if (/Linux/i.test(ua))       return { device_make: "Linux", device_model: "Desktop" };
  if (/CrOS/i.test(ua))        return { device_make: "Google", device_model: "Chromebook" };

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
  try {
    const c = document.createElement('canvas');
    c.width = 200; c.height = 50;
    const ctx = c.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(10, 0, 100, 30);
    ctx.fillStyle = '#069';
    ctx.fillText('fingerprint', 2, 15);
    parts.push(c.toDataURL());
  } catch (e) { parts.push('no-canvas'); }

  // WebGL renderer
  try {
    const gl = document.createElement('canvas').getContext('webgl');
    if (gl) {
      const dbg = gl.getExtension('WEBGL_debug_renderer_info');
      if (dbg) parts.push(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL));
    }
  } catch (e) { parts.push('no-webgl'); }

  // Hash it
  const raw = parts.join('|');
  const msgBuf = new TextEncoder().encode(raw);
  const hashBuf = await crypto.subtle.digest('SHA-256', msgBuf);
  const hashArr = Array.from(new Uint8Array(hashBuf));
  cachedFingerprint = hashArr.map(b => b.toString(16).padStart(2, '0')).join('');
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
  sessionStorage.setItem('verificationResult', JSON.stringify(data));

  // Extract and store token for ownership claiming
  if (scannedUrl) {
    const token = extractTokenFromUrlText(scannedUrl);
    if (token) {
      sessionStorage.setItem('currentToken', token);
    }
  }

  window.location.href = '/results';
}

// -------------------------------------------------------------
// Camera
// -------------------------------------------------------------
async function startCamera() {
  cameraPrompt.classList.add('hidden');
  scanOverlay.classList.remove('hidden');
  previewImage.classList.add('hidden');

  try {
    const constraints = {
      video: {
        facingMode: 'environment',
        width: { ideal: 1280 },
        height: { ideal: 1280 }
      }
    };

    videoStream = await navigator.mediaDevices.getUserMedia(constraints);
    video.srcObject = videoStream;

    video.addEventListener('loadedmetadata', () => {
      startScanning();
    }, { once: true });

  } catch (error) {
    console.error('Camera error:', error);
    cameraPrompt.classList.remove('hidden');
    scanOverlay.classList.add('hidden');
  }
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

function startScanning() {
  const canvas = document.createElement('canvas');
  const context = canvas.getContext('2d');

  scanningInterval = setInterval(() => {
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      context.drawImage(video, 0, 0, canvas.width, canvas.height);

      const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imageData.data, imageData.width, imageData.height);

      if (code) {
        stopCamera();

        const decodedUrl = code.data;
        const token = extractTokenFromUrlText(decodedUrl);

        if (!token) {
          goToResults({
            status: "FAKE",
            verified: false,
            reason: "QR code was detected but does not contain a valid verification token. This is not an authenticated product QR code.",
            product: {}
          });
          return;
        }

        canvas.toBlob(async (blob) => {
          try {
            const resp = await verifyWithBackend(decodedUrl, blob);
            goToResults(resp, decodedUrl);
          } catch (err) {
            goToResults({
              status: "FAKE",
              verified: false,
              reason: err.message || "Server verification failed. Please try again.",
              product: {}
            });
          }
        }, "image/png");
      }
    }
  }, 300);
}

// -------------------------------------------------------------
// File Upload Handling
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

    decodeQRFromImage(e.target.result, file);
  };
  reader.readAsDataURL(file);
}

function decodeQRFromImage(imageSrc, originalFile) {
  const img = new Image();
  img.onload = async () => {
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');

    canvas.width = img.width;
    canvas.height = img.height;
    context.drawImage(img, 0, 0);

    const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(imageData.data, imageData.width, imageData.height);

    if (!code) {
      goToResults({
        status: "FAKE",
        verified: false,
        reason: "No QR code could be detected in the uploaded image. Please upload a clear image of the product's QR code.",
        product: {}
      });
      return;
    }

    const decodedUrl = code.data;
    const token = extractTokenFromUrlText(decodedUrl);

    if (!token) {
      goToResults({
        status: "FAKE",
        verified: false,
        reason: "QR code was detected but does not contain a valid verification token. This is not an authenticated product QR code.",
        product: {}
      });
      return;
    }

    try {
      const resp = await verifyWithBackend(decodedUrl, originalFile);
      goToResults(resp, decodedUrl);
    } catch (err) {
      goToResults({
        status: "FAKE",
        verified: false,
        reason: err.message || "Server verification failed. Please try again.",
        product: {}
      });
    }
  };

  img.src = imageSrc;
}

// ===== Initialize =====
document.addEventListener('DOMContentLoaded', () => {
  document.documentElement.style.scrollBehavior = 'smooth';
  startCamera();
});

window.addEventListener('beforeunload', () => {
  stopCamera();
});
