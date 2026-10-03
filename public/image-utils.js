// ============================================
// IMAGE UTILITIES (shared by the resident report page and the
// municipal after-repair upload)
// ============================================

// Photos are shrunk before upload: modern phone photos are several MB,
// which would exceed the server's upload limit once base64-encoded.
const MAX_IMAGE_DIMENSION = 1600;

// Re-encodes the photo as a JPEG no larger than MAX_IMAGE_DIMENSION.
function compressImage(file) {
    return new Promise((resolve, reject) => {
        const url = URL.createObjectURL(file);
        const img = new Image();

        img.onload = () => {
            const scale = Math.min(1, MAX_IMAGE_DIMENSION / Math.max(img.naturalWidth, img.naturalHeight));
            const canvas = document.createElement("canvas");
            canvas.width = Math.round(img.naturalWidth * scale);
            canvas.height = Math.round(img.naturalHeight * scale);
            canvas.getContext("2d").drawImage(img, 0, 0, canvas.width, canvas.height);
            URL.revokeObjectURL(url);
            resolve(canvas.toDataURL("image/jpeg", 0.85));
        };
        img.onerror = () => {
            URL.revokeObjectURL(url);
            reject(new Error("Unreadable image"));
        };

        img.src = url;
    });
}
