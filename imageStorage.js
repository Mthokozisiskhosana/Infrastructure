// ============================================
// IMAGE STORAGE
// Report photos and profile pictures arrive from the browser as base64
// data URLs. Instead of storing those (large) strings in the database,
// they're decoded and written to /uploads as files, and the database
// only keeps a short URL like "/uploads/reports/<uuid>.jpg".
// ============================================

const fs = require("fs/promises");
const path = require("path");
const crypto = require("crypto");

const UPLOADS_DIR = path.join(__dirname, "uploads");
const FOLDERS = ["reports", "profiles", "repairs"];

const EXTENSIONS = {
    "image/jpeg": "jpg",
    "image/jpg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
    "image/gif": "gif"
};

// Strict shape check — the data URL is decoded, never echoed back into HTML.
const DATA_URL_REGEX = /^data:(image\/[a-zA-Z0-9.+-]+);base64,([A-Za-z0-9+/]+={0,2})$/;

// Only URLs this module generated are accepted, so a stored value can
// never point outside the uploads folder (no "../" tricks).
const STORED_URL_REGEX = /^\/uploads\/(reports|profiles|repairs)\/[0-9a-f-]{36}\.(jpg|png|webp|gif)$/;

/**
 * Returns { buffer, ext } for a valid JPEG/PNG/WebP/GIF data URL, or null.
 */
function parseImageDataUrl(value) {
    if (typeof value !== "string") return null;
    const match = DATA_URL_REGEX.exec(value);
    if (!match) return null;

    const ext = EXTENSIONS[match[1].toLowerCase()];
    if (!ext) return null;

    const buffer = Buffer.from(match[2], "base64");
    if (buffer.length === 0) return null;

    return { buffer, ext };
}

function isStoredImageUrl(value) {
    return typeof value === "string" && STORED_URL_REGEX.test(value);
}

function storedUrlToPath(url) {
    if (!isStoredImageUrl(url)) return null;
    return path.join(UPLOADS_DIR, url.slice("/uploads/".length));
}

/**
 * Writes a parsed image to uploads/<folder>/ and returns its public URL.
 */
async function saveImage(parsed, folder) {
    if (!FOLDERS.includes(folder)) throw new Error(`Unknown upload folder: ${folder}`);

    const dir = path.join(UPLOADS_DIR, folder);
    await fs.mkdir(dir, { recursive: true });

    const filename = `${crypto.randomUUID()}.${parsed.ext}`;
    await fs.writeFile(path.join(dir, filename), parsed.buffer);

    return `/uploads/${folder}/${filename}`;
}

/**
 * Returns the raw bytes of a stored image (or of a legacy data URL that
 * hasn't been migrated yet), or null if it can't be read.
 */
async function readImage(value) {
    const filePath = storedUrlToPath(value);
    if (filePath) {
        try {
            return await fs.readFile(filePath);
        } catch (err) {
            return null;
        }
    }
    const parsed = parseImageDataUrl(value);
    return parsed ? parsed.buffer : null;
}

/**
 * Removes a stored image file. Silently ignores missing files and
 * anything that isn't one of our upload URLs (e.g. a legacy data URL).
 */
async function deleteImage(value) {
    const filePath = storedUrlToPath(value);
    if (!filePath) return;
    try {
        await fs.unlink(filePath);
    } catch (err) {
        if (err.code !== "ENOENT") {
            console.log(`[images] Could not delete ${value}:`, err.message);
        }
    }
}

module.exports = {
    UPLOADS_DIR,
    parseImageDataUrl,
    isStoredImageUrl,
    saveImage,
    readImage,
    deleteImage
};
