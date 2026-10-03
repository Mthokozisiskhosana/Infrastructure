// ============================================
// IMAGE STORAGE
// Report photos and profile pictures arrive from the browser as base64
// data URLs. Instead of storing those (large) strings in the database,
// they're decoded and saved as files, and the database only keeps a short
// URL like "/uploads/reports/<uuid>.jpg".
//
// Two backends, chosen automatically:
//   - Local disk (default): files go in ./uploads — used when running on
//     your own PC.
//   - Supabase Storage: used when SUPABASE_URL and SUPABASE_SERVICE_KEY are
//     set (e.g. on Render, whose free servers wipe local files on every
//     restart). The stored URL keeps the same "/uploads/..." shape, and
//     server.js redirects those requests to Supabase, so no page changes.
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
const CONTENT_TYPES = { jpg: "image/jpeg", png: "image/png", webp: "image/webp", gif: "image/gif" };

// Strict shape check — the data URL is decoded, never echoed back into HTML.
const DATA_URL_REGEX = /^data:(image\/[a-zA-Z0-9.+-]+);base64,([A-Za-z0-9+/]+={0,2})$/;

// Only URLs this module generated are accepted, so a stored value can
// never point outside the uploads folder/bucket (no "../" tricks).
const STORED_URL_REGEX = /^\/uploads\/(reports|profiles|repairs)\/[0-9a-f-]{36}\.(jpg|png|webp|gif)$/;

// ---------- Supabase configuration ----------
const SUPABASE_URL = (process.env.SUPABASE_URL || "").replace(/\/+$/, "");
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY || "";
const SUPABASE_BUCKET = process.env.SUPABASE_BUCKET || "ciris-uploads";
const USE_SUPABASE = Boolean(SUPABASE_URL && SUPABASE_KEY);

function supabaseHeaders(extra = {}) {
    // New-style secret keys ("sb_secret_...") go in the apikey header only;
    // legacy service_role keys are JWTs and are also sent as a Bearer token.
    const headers = { apikey: SUPABASE_KEY, ...extra };
    if (SUPABASE_KEY.startsWith("eyJ")) headers.Authorization = `Bearer ${SUPABASE_KEY}`;
    return headers;
}

/** Public address of a stored image in the Supabase bucket. */
function publicImageUrl(storedUrl) {
    if (!USE_SUPABASE || !isStoredImageUrl(storedUrl)) return null;
    return `${SUPABASE_URL}/storage/v1/object/public/${SUPABASE_BUCKET}/${storedUrl.slice("/uploads/".length)}`;
}

/**
 * Creates the public photo bucket on first run if it doesn't exist yet,
 * so there's nothing to set up by hand in the Supabase dashboard.
 */
async function ensureStorageReady() {
    if (!USE_SUPABASE) {
        console.log("🖼️  Image storage: local disk (./uploads)");
        return;
    }
    try {
        const check = await fetch(`${SUPABASE_URL}/storage/v1/bucket/${SUPABASE_BUCKET}`, { headers: supabaseHeaders() });
        if (check.ok) {
            console.log(`🖼️  Image storage: Supabase bucket "${SUPABASE_BUCKET}"`);
            return;
        }
        const create = await fetch(`${SUPABASE_URL}/storage/v1/bucket`, {
            method: "POST",
            headers: supabaseHeaders({ "Content-Type": "application/json" }),
            body: JSON.stringify({ id: SUPABASE_BUCKET, name: SUPABASE_BUCKET, public: true })
        });
        if (create.ok) {
            console.log(`🖼️  Image storage: created Supabase bucket "${SUPABASE_BUCKET}"`);
        } else {
            console.log(`❌ Could not create Supabase bucket "${SUPABASE_BUCKET}" (${create.status}): ${await create.text()}`);
        }
    } catch (err) {
        console.log("❌ Could not reach Supabase Storage:", err.message);
    }
}

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
 * Saves a parsed image under <folder>/ and returns its "/uploads/..." URL.
 */
async function saveImage(parsed, folder) {
    if (!FOLDERS.includes(folder)) throw new Error(`Unknown upload folder: ${folder}`);

    const filename = `${crypto.randomUUID()}.${parsed.ext}`;
    const objectPath = `${folder}/${filename}`;

    if (USE_SUPABASE) {
        const res = await fetch(`${SUPABASE_URL}/storage/v1/object/${SUPABASE_BUCKET}/${objectPath}`, {
            method: "POST",
            headers: supabaseHeaders({ "Content-Type": CONTENT_TYPES[parsed.ext], "x-upsert": "false" }),
            body: parsed.buffer
        });
        if (!res.ok) {
            throw new Error(`Supabase upload failed (${res.status}): ${await res.text()}`);
        }
    } else {
        const dir = path.join(UPLOADS_DIR, folder);
        await fs.mkdir(dir, { recursive: true });
        await fs.writeFile(path.join(dir, filename), parsed.buffer);
    }

    return `/uploads/${objectPath}`;
}

/**
 * Returns the raw bytes of a stored image (or of a legacy data URL that
 * hasn't been migrated yet), or null if it can't be read.
 */
async function readImage(value) {
    if (isStoredImageUrl(value)) {
        try {
            if (USE_SUPABASE) {
                const res = await fetch(`${SUPABASE_URL}/storage/v1/object/${SUPABASE_BUCKET}/${value.slice("/uploads/".length)}`, {
                    headers: supabaseHeaders()
                });
                return res.ok ? Buffer.from(await res.arrayBuffer()) : null;
            }
            return await fs.readFile(storedUrlToPath(value));
        } catch (err) {
            return null;
        }
    }
    const parsed = parseImageDataUrl(value);
    return parsed ? parsed.buffer : null;
}

/**
 * Removes a stored image. Silently ignores missing files and anything
 * that isn't one of our upload URLs (e.g. a legacy data URL).
 */
async function deleteImage(value) {
    if (!isStoredImageUrl(value)) return;

    if (USE_SUPABASE) {
        try {
            const res = await fetch(`${SUPABASE_URL}/storage/v1/object/${SUPABASE_BUCKET}`, {
                method: "DELETE",
                headers: supabaseHeaders({ "Content-Type": "application/json" }),
                body: JSON.stringify({ prefixes: [value.slice("/uploads/".length)] })
            });
            if (!res.ok) console.log(`[images] Could not delete ${value} from Supabase (${res.status})`);
        } catch (err) {
            console.log(`[images] Could not delete ${value}:`, err.message);
        }
        return;
    }

    try {
        await fs.unlink(storedUrlToPath(value));
    } catch (err) {
        if (err.code !== "ENOENT") {
            console.log(`[images] Could not delete ${value}:`, err.message);
        }
    }
}

module.exports = {
    UPLOADS_DIR,
    USE_SUPABASE,
    ensureStorageReady,
    publicImageUrl,
    parseImageDataUrl,
    isStoredImageUrl,
    saveImage,
    readImage,
    deleteImage
};
