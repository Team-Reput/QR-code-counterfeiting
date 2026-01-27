// ===== Global Variables =====
let currentMode = 'scan';
let videoStream = null;
let scanningInterval = null;

// ===== DOM Elements =====
const fileInput = document.getElementById('fileInput');
const previewArea = document.getElementById('previewArea');
const previewImage = document.getElementById('previewImage');

// ===== Modal Handling =====
function showOptions() {
    const modal = document.getElementById('optionsModal');
    modal.classList.remove('hidden');
}

function closeOptions() {
    const modal = document.getElementById('optionsModal');
    modal.classList.add('hidden');
}

function selectMode(mode) {
    currentMode = mode;
    closeOptions();

    const uploadSection = document.getElementById('uploadSection');
    const scanSection = document.getElementById('scanSection');
    const resultSection = document.getElementById('resultSection');

    // Hide result section when switching modes
    resultSection.classList.add('hidden');

    if (mode === 'upload') {
        uploadSection.classList.remove('hidden');
        scanSection.classList.add('hidden');
        stopCamera();
        // Trigger file input
        setTimeout(() => {
            fileInput.click();
        }, 100);
    } else {
        scanSection.classList.remove('hidden');
        uploadSection.classList.add('hidden');
        startCamera();
    }
}

// Close modal when clicking outside
document.addEventListener('click', (e) => {
    const modal = document.getElementById('optionsModal');
    if (e.target === modal) {
        closeOptions();
    }
});

// ===== File Upload Handling =====
// File input change
fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
        handleFile(file);
    }
});

// Handle uploaded file
function handleFile(file) {
    const reader = new FileReader();

    reader.onload = (e) => {
        previewImage.src = e.target.result;
        previewArea.classList.remove('hidden');

        // Decode QR code from image
        decodeQRFromImage(e.target.result);
    };

    reader.readAsDataURL(file);
}

// Reset upload
function resetUpload() {
    previewArea.classList.add('hidden');
    fileInput.value = '';
    document.getElementById('resultSection').classList.add('hidden');
}

// ===== Camera Scanning =====
async function startCamera() {
    try {
        const constraints = {
            video: {
                facingMode: 'environment',
                width: { ideal: 1280 },
                height: { ideal: 720 }
            }
        };

        videoStream = await navigator.mediaDevices.getUserMedia(constraints);
        const video = document.getElementById('video');
        video.srcObject = videoStream;

        // Add immersive class
        document.body.classList.add('scanning-mode');

        // Start scanning after video is ready
        video.addEventListener('loadedmetadata', () => {
            startScanning();
        });

    } catch (error) {
        console.error('Error accessing camera:', error);
        showResult(false, 'Camera access denied. Please allow camera permissions.');
    }
}

function stopCamera() {
    if (videoStream) {
        videoStream.getTracks().forEach(track => track.stop());
        videoStream = null;
    }
    document.body.classList.remove('scanning-mode');

    if (scanningInterval) {
        clearInterval(scanningInterval);
        scanningInterval = null;
    }
}

function startScanning() {
    const video = document.getElementById('video');
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
                showResult(true, code.data);
            }
        }
    }, 300); // Scan every 300ms
}

// ===== QR Code Decoding from Image =====
function decodeQRFromImage(imageSrc) {
    const img = new Image();
    img.onload = () => {
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');

        canvas.width = img.width;
        canvas.height = img.height;
        context.drawImage(img, 0, 0);

        const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height);

        if (code) {
            showResult(true, code.data);
        } else {
            showResult(false, 'No QR code detected in the image. Please try another image.');
        }
    };

    img.src = imageSrc;
}

// ===== Result Display =====
function showResult(success, data) {
    const resultSection = document.getElementById('resultSection');
    const resultIcon = document.getElementById('resultIcon');
    const resultTitle = document.getElementById('resultTitle');
    const resultValue = document.getElementById('resultValue');

    // Remove immersive class to show result UI
    document.body.classList.remove('scanning-mode');

    // Update result content
    if (success) {
        resultIcon.classList.remove('error');
        resultIcon.classList.add('success');
        resultIcon.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
        `;
        resultTitle.textContent = 'QR Code Detected Successfully!';
        resultValue.textContent = data;
    } else {
        resultIcon.classList.remove('success');
        resultIcon.classList.add('error');
        resultIcon.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
        `;
        resultTitle.textContent = 'Scan Failed';
        resultValue.textContent = data;
    }

    // Show result section
    resultSection.classList.remove('hidden');

    // Scroll to result
    resultSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Reset scanner
function resetScanner() {
    document.getElementById('resultSection').classList.add('hidden');

    if (currentMode === 'upload') {
        resetUpload();
    } else {
        startCamera();
    }
}

// ===== Initialize =====
document.addEventListener('DOMContentLoaded', () => {
    // Add smooth scroll behavior
    document.documentElement.style.scrollBehavior = 'smooth';

    // Automatically start camera in 'scan' mode
    if (currentMode === 'scan') {
        startCamera();
    }
});

// ===== Cleanup on page unload =====
window.addEventListener('beforeunload', () => {
    stopCamera();
});
