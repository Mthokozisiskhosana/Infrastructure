require("dotenv").config();
const path = require("path");
const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { createMailer } = require("./mailer");
const { validatePasswordStrength } = require("./passwordPolicy");
const {
    createLoginSecurity,
    loginLockSeconds,
    formatDuration,
    LOGIN_MAX_FAILURES,
    IP_MAX_FAILURES,
    IP_LOCK_SECONDS,
    CODE_MAX_FAILURES
} = require("./loginSecurity");
const {
    UPLOADS_DIR,
    USE_SUPABASE,
    ensureStorageReady,
    publicImageUrl,
    parseImageDataUrl,
    isStoredImageUrl,
    saveImage,
    readImage,
    deleteImage
} = require("./imageStorage");

const app = express();

// On Render, requests arrive through Render's proxy — trust it so req.ip is
// the visitor's real address (used for per-address login limits). Not
// enabled locally, where the header could simply be faked.
if (process.env.RENDER || process.env.TRUST_PROXY === "true") {
    app.set("trust proxy", 1);
}
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Serve only the frontend files (put your .html/.css/.js in a "public" folder)
// instead of the whole project root — keeps server.js, package.json, node_modules
// etc. from being served as static files.
app.use(express.static(path.join(__dirname, "public")));

// Uploaded report photos / profile pictures. Filenames are random UUIDs
// that never change, so browsers can cache them for a long time.
// When photos live in Supabase Storage (deployed), the same "/uploads/..."
// addresses are redirected there, so pages and the database don't change.
if (USE_SUPABASE) {
    app.get("/uploads/:folder/:file", (req, res) => {
        const target = publicImageUrl(`/uploads/${req.params.folder}/${req.params.file}`);
        if (!target) return res.status(404).send("Not found");
        res.set("Cache-Control", "public, max-age=604800, immutable");
        res.redirect(302, target);
    });
} else {
    app.use("/uploads", express.static(UPLOADS_DIR, { maxAge: "7d", immutable: true }));
}
ensureStorageReady();

app.get("/", (req, res) => {
    res.redirect("/login.html");
});

app.get("/api/health", (req, res) => {
    res.json({ message: "Server is running!" });
});

const SALT_ROUNDS = 12;
const RESET_CODE_TTL_MINUTES = 10;
const RESEND_COOLDOWN_SECONDS = 30;

// ======================================
// JWT CONFIG
// ======================================
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = "8h";

if (!JWT_SECRET) {
    console.error("❌ JWT_SECRET is not set in .env — refusing to start.");
    process.exit(1);
}

function generateToken(user) {
    return jwt.sign(
        { id: user.id, role: user.role },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
    );
}

function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

    if (!token) {
        return res.status(401).json({ message: "Authentication required" });
    }

    try {
        const payload = jwt.verify(token, JWT_SECRET);
        req.user = { id: payload.id, role: payload.role };
        next();
    } catch (err) {
        return res.status(401).json({ message: "Invalid or expired token" });
    }
}

function requireRole(...allowedRoles) {
    return (req, res, next) => {
        if (!req.user || !allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ message: "You don't have permission to access this resource" });
        }
        next();
    };
}

// ======================================
// POSTGRESQL CONFIG
// ======================================
// Render (and most managed Postgres hosts) require SSL for external
// connections, and Render also gives you a single DATABASE_URL instead of
// separate host/user/password vars. This supports either:
//   - Set DATABASE_URL (Render Postgres "Internal/External Database URL"), or
//   - Keep using DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD like before.
// Set DB_SSL=false only for a local Postgres that doesn't use SSL.
const useSSL = process.env.DB_SSL !== "false";

const pool = process.env.DATABASE_URL
    ? new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: useSSL ? { rejectUnauthorized: false } : false,
        max: 10,
        idleTimeoutMillis: 30000
    })
    : new Pool({
        host: process.env.DB_HOST,
        port: Number(process.env.DB_PORT) || 5432,
        database: process.env.DB_NAME,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        ssl: useSSL ? { rejectUnauthorized: false } : false,
        max: 10,
        idleTimeoutMillis: 30000
    });

const loginSecurity = createLoginSecurity(pool);

pool.connect()
    .then(client => {
        console.log("✅ Connected to PostgreSQL");
        client.release();
        return loginSecurity.ensureTable().then(() => loginSecurity.startCleanup());
    })
    .catch(err => {
        console.log("❌ DB Connection Failed:", err.message);
        if (err.code === "28P01") {
            // Most common deployment mistake — spell out what to check.
            console.log("   → The username or password in DATABASE_URL is wrong. Check that:");
            console.log("     • [YOUR-PASSWORD] was replaced, and the square brackets removed");
            console.log("     • special characters in the password (@ # / % : ? &) are URL-encoded");
            console.log("     • with Supabase's Session pooler, the user is postgres.<project-ref>, not just postgres");
        }
    });

// ======================================
// EMAIL TRANSPORT
// Brevo's web API when BREVO_API_KEY is set (deployed), otherwise SMTP —
// see mailer.js. Same sendMail({ from, to, subject, html }) either way.
// ======================================
const transporter = createMailer();

function generateOtp() {
    return crypto.randomInt(0, 1000000).toString().padStart(6, "0");
}

function hashOtp(code) {
    return crypto.createHash("sha256").update(code).digest("hex");
}

async function sendResetCodeEmail(toEmail, code) {
    await transporter.sendMail({
        from: process.env.SMTP_FROM || '"Community Portal" <no-reply@communityportal.local>',
        to: toEmail,
        subject: "Your Community Portal password reset code",
        html: `
            <p>Use this code in the app to reset your password:</p>
            <p style="font-size: 28px; font-weight: bold; letter-spacing: 4px;">${code}</p>
            <p>This code expires in ${RESET_CODE_TTL_MINUTES} minutes. If you didn't request this, you can ignore this email — your password will not change.</p>
        `
    });
}

// ======================================
// NOTIFICATIONS helper
// ======================================
async function createNotification(type, relatedId, title, message, userId = null) {
    try {
        await pool.query(
            `INSERT INTO Notifications (type, related_id, title, message, user_id)
             VALUES ($1, $2, $3, $4, $5)`,
            [type, relatedId, title, message, userId]
        );
    } catch (err) {
        console.log(`[notification] Failed to create ${type} notification:`, err.message);
    }
}

function truncate(text, maxLen) {
    if (!text) return "";
    return text.length > maxLen ? text.slice(0, maxLen - 3) + "..." : text;
}

async function getUserDisplayName(userId) {
    try {
        const result = await pool.query(
            "SELECT first_name, last_name FROM Users WHERE id = $1",
            [userId]
        );
        if (result.rows.length === 0) return "A community member";
        const { first_name, last_name } = result.rows[0];
        return `${first_name || ""} ${last_name || ""}`.trim() || "A community member";
    } catch (err) {
        console.log("[notification] Could not look up submitter name:", err.message);
        return "A community member";
    }
}

// ======================================
// REGISTER API
// ======================================
// POPIA consent wording shown on the registration form. If the wording
// ever changes, bump the version so each user's record shows exactly
// which text they agreed to.
const POPIA_CONSENT_VERSION = "2026-10-v1";

app.post("/register", async (req, res) => {
    const { first_name, last_name, email, phone, password, popia_consent } = req.body;

    if (popia_consent !== true) {
        return res.status(400).json({ message: "You must consent to the processing of your personal information (POPIA) to create an account." });
    }

    const allowedDomains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com'];
    const emailDomain = (email || "").split('@')[1];

    if (!emailDomain || !allowedDomains.includes(emailDomain.toLowerCase())) {
        return res.status(400).json({ message: "Please use a personal email from an allowed domain (gmail.com, yahoo.com, outlook.com, hotmail.com, icloud.com)" });
    }

    const phoneRegex = /^(\+27|0)[6-8][0-9]{8}$/;
    if (!phoneRegex.test(phone)) {
        return res.status(400).json({ message: "Please enter a valid South African phone number (e.g., 0712345678 or +27712345678)" });
    }

    const strength = validatePasswordStrength(password);
    if (!strength.valid) {
        return res.status(400).json({ message: strength.message });
    }

    try {
        const checkUser = await pool.query(
            "SELECT id FROM Users WHERE email = $1",
            [email]
        );

        if (checkUser.rows.length > 0) {
            return res.status(400).json({ message: "Email already exists" });
        }

        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

        await pool.query(
            `INSERT INTO Users (first_name, last_name, email, phone, password, role,
                                popia_consent_at, popia_consent_version)
             VALUES ($1, $2, $3, $4, $5, 'community_member', NOW(), $6)`,
            [first_name, last_name, email, phone, passwordHash, POPIA_CONSENT_VERSION]
        );

        res.json({ message: "User registered successfully" });

    } catch (err) {
        console.log("FULL ERROR:", err);
        // Details stay in the server log — database errors can reveal
        // connection details and mean nothing to the person registering.
        res.status(500).json({ message: "Could not create your account right now. Please try again later." });
    }
});

// ======================================
// LOGIN API
// ======================================
// Compared against when the email doesn't exist, so a wrong email takes as
// long as a wrong password — response time can't reveal who is registered.
const DUMMY_PASSWORD_HASH = bcrypt.hashSync("ciris-timing-placeholder", SALT_ROUNDS);

function lockedResponse(seconds) {
    return {
        message: `Too many failed login attempts. Please wait ${formatDuration(seconds)} before trying again.`,
        locked: true,
        retry_after: seconds
    };
}

async function sendLockoutAlert(email) {
    const timeStr = new Date().toLocaleString('en-ZA', { timeZone: 'Africa/Johannesburg' });
    await sendSecurityEmail(
        email,
        "Security Alert: Several failed login attempts",
        `
        <div style="font-family:Segoe UI,sans-serif;max-width:500px;margin:auto;">
            <h2 style="color:#1e3c72;">Failed login attempts</h2>
            <p>Someone entered the wrong password for your CIRIS account ${LOGIN_MAX_FAILURES} times, so sign-in was paused for a short while.</p>
            <p><strong>Time:</strong> ${timeStr}</p>
            <hr style="border:none;border-top:1px solid #e2e8f0;">
            <p style="font-size:13px;color:#64748b;">
                If this was you, you can try again shortly. If it wasn't, we recommend resetting your password.
            </p>
        </div>
        `
    );
}

app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "Email and password are required" });
    }

    const accountKey = `login:${String(email).trim().toLowerCase()}`;
    const ipKey = `ip:${req.ip}`;

    try {
        // 1. Refuse while the account or this address is locked
        const lockedFor = await loginSecurity.getLockSeconds([accountKey, ipKey]);
        if (lockedFor > 0) {
            return res.status(429).json(lockedResponse(lockedFor));
        }

        const result = await pool.query(
            `SELECT id, first_name, last_name, email, phone, password, role, must_change_password
             FROM Users
             WHERE email = $1`,
            [email]
        );

        const user = result.rows[0];
        const match = await bcrypt.compare(password, user ? user.password : DUMMY_PASSWORD_HASH);

        // 2. Wrong email or password: count it (unknown emails are counted the
        //    same way, so lockouts don't reveal which emails are registered)
        if (!user || !match) {
            const ipResult = await loginSecurity.recordFailure(ipKey, {
                limit: IP_MAX_FAILURES,
                lockFor: () => IP_LOCK_SECONDS
            });
            const accountResult = await loginSecurity.recordFailure(accountKey, {
                limit: LOGIN_MAX_FAILURES,
                lockFor: loginLockSeconds
            });

            if (accountResult.lockedFor) {
                // Email the owner on the first lockout only, so an attacker
                // can't flood their inbox by triggering lock after lock.
                if (user && accountResult.lockouts === 1) {
                    sendLockoutAlert(user.email);
                }
                return res.status(429).json(lockedResponse(accountResult.lockedFor));
            }
            if (ipResult.lockedFor) {
                return res.status(429).json(lockedResponse(ipResult.lockedFor));
            }

            const left = accountResult.attemptsLeft;
            return res.status(401).json({
                message: left <= 3
                    ? `Invalid email or password. ${left} attempt${left === 1 ? "" : "s"} left before sign-in is paused.`
                    : "Invalid email or password",
                attempts_left: left
            });
        }

        // 3. Success: forget this account's failures
        await loginSecurity.clear(accountKey);

        const token = generateToken(user);

        res.json({
            token,
            id: user.id,
            first_name: user.first_name,
            last_name: user.last_name,
            email: user.email,
            phone: user.phone,
            role: user.role,
            must_change_password: user.must_change_password
        });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

// ======================================
// FORGOT PASSWORD — STEP 1
// ======================================
app.post("/forgot-password", async (req, res) => {
    const { email } = req.body;
    const genericResponse = { message: "If that email is registered, a verification code has been sent." };

    if (!email) {
        return res.status(400).json({ message: "Email is required" });
    }

    try {
        const checkUser = await pool.query(
            "SELECT id, reset_token_expiry FROM Users WHERE email = $1",
            [email]
        );

        if (checkUser.rows.length === 0) {
            return res.json(genericResponse);
        }

        // Resend cooldown (matches the 30s countdown on forgortpassword.html):
        // a code issued less than RESEND_COOLDOWN_SECONDS ago isn't replaced,
        // so nobody can flood someone's inbox with reset emails. The reply is
        // the same either way, so it doesn't reveal whether the email exists.
        const expiry0 = checkUser.rows[0].reset_token_expiry;
        const issuedSecondsAgo = expiry0
            ? RESET_CODE_TTL_MINUTES * 60 - (new Date(expiry0) - Date.now()) / 1000
            : Infinity;
        if (issuedSecondsAgo < RESEND_COOLDOWN_SECONDS) {
            return res.json(genericResponse);
        }

        // A fresh code gets a fresh set of guesses
        await loginSecurity.clear(resetKey(email));

        const code = generateOtp();
        const expiry = new Date(Date.now() + RESET_CODE_TTL_MINUTES * 60 * 1000);

        await pool.query(
            `UPDATE Users
             SET reset_token = $1, reset_token_expiry = $2
             WHERE email = $3`,
            [hashOtp(code), expiry, email]
        );

        try {
            await sendResetCodeEmail(email, code);
        } catch (mailErr) {
            // Cancel the unsent code so the resend cooldown doesn't silently
            // swallow the next attempt, and say plainly that email failed.
            console.log(`[reset] Could not send reset code to ${email}:`, mailErr.message);
            await pool.query(
                "UPDATE Users SET reset_token = NULL, reset_token_expiry = NULL WHERE email = $1",
                [email]
            );
            return res.status(503).json({ message: "We couldn't send the email right now. Please try again in a few minutes." });
        }

        res.json(genericResponse);

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Something went wrong. Please try again later." });
    }
});

// ======================================
// RESET-CODE CHECK (shared by steps 2 and 3)
// A 6-digit code has only a million combinations, so without a limit it
// could simply be guessed within its 10 minutes. After CODE_MAX_FAILURES
// wrong guesses the code is cancelled and a new one must be requested.
// ======================================
function resetKey(email) {
    return `reset:${String(email).trim().toLowerCase()}`;
}

async function checkResetCode(email, code) {
    const result = await pool.query(
        `SELECT id, reset_token, reset_token_expiry
         FROM Users
         WHERE email = $1`,
        [email]
    );
    const user = result.rows[0];

    if (!user || !user.reset_token) {
        return { ok: false, message: "Invalid or expired code. Please request a new one." };
    }

    const notExpired = user.reset_token_expiry && new Date(user.reset_token_expiry) > new Date();
    if (!notExpired) {
        return { ok: false, message: "This code has expired. Please request a new one." };
    }

    if (user.reset_token !== hashOtp(String(code))) {
        const attempt = await loginSecurity.recordFailure(resetKey(email), { limit: CODE_MAX_FAILURES });
        if (attempt.limitReached) {
            await pool.query(
                "UPDATE Users SET reset_token = NULL, reset_token_expiry = NULL WHERE id = $1",
                [user.id]
            );
            return { ok: false, message: "Too many incorrect codes. This code has been cancelled — please request a new one." };
        }
        const left = attempt.attemptsLeft;
        return { ok: false, message: `Incorrect code. ${left} attempt${left === 1 ? "" : "s"} left.` };
    }

    return { ok: true, user };
}

// ======================================
// FORGOT PASSWORD — STEP 2
// ======================================
app.post("/verify-code", async (req, res) => {
    const { email, code } = req.body;

    if (!email || !code) {
        return res.status(400).json({ message: "Invalid or expired code." });
    }

    try {
        const check = await checkResetCode(email, code);
        if (!check.ok) {
            return res.status(400).json({ message: check.message });
        }

        res.json({ message: "Code verified" });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Something went wrong. Please try again." });
    }
});

// ======================================
// FORGOT PASSWORD — STEP 3
// ======================================
app.post("/reset-password", async (req, res) => {
    const { email, code, password } = req.body;

    if (!email || !code) {
        return res.status(400).json({ message: "Missing email or verification code." });
    }

    const strength = validatePasswordStrength(password);
    if (!strength.valid) {
        return res.status(400).json({ message: strength.message });
    }

    try {
        const check = await checkResetCode(email, code);
        if (!check.ok) {
            return res.status(400).json({ message: check.message });
        }
        const user = check.user;

        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

        await pool.query(
            `UPDATE Users
             SET password = $1, reset_token = NULL, reset_token_expiry = NULL
             WHERE id = $2`,
            [passwordHash, user.id]
        );

        // New password: clear the code guesses and any login lock on this account
        await loginSecurity.clear(resetKey(email));
        await loginSecurity.clear(`login:${String(email).trim().toLowerCase()}`);

        res.json({ message: "Password updated successfully. You can now log in." });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

// ======================================
// SUBMIT REPORT API
// ======================================
function haversineDistance(lat1, lon1, lat2, lon2) {
    const R = 6371000;
    const toRad = deg => deg * Math.PI / 180;
    const dLat = toRad(lat2 - lat1);
    const dLon = toRad(lon2 - lon1);
    const a = Math.sin(dLat / 2) ** 2 +
              Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
              Math.sin(dLon / 2) ** 2;
    return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function parseLocation(locationStr) {
    if (!locationStr) return null;
    const parts = locationStr.split(',').map(s => parseFloat(s.trim()));
    if (parts.length !== 2 || parts.some(isNaN)) return null;
    return { lat: parts[0], lng: parts[1] };
}

const DUPLICATE_RADIUS_METERS = 100;

// ======================================
// AUTO-ARCHIVING
// ======================================
const ARCHIVE_DELAY_HOURS = Number(process.env.ARCHIVE_DELAY_HOURS) || 24;
const ARCHIVE_CHECK_INTERVAL_MS = 15 * 60 * 1000;

async function archiveOldResolvedReports() {
    try {
        const result = await pool.query(
            `UPDATE Reports
             SET is_archived = true
             WHERE status = 'Resolved'
               AND is_archived = false
               AND resolved_at IS NOT NULL
               AND resolved_at <= NOW() - ($1 || ' hours')::interval
             RETURNING id`,
            [ARCHIVE_DELAY_HOURS]
        );
        if (result.rows.length > 0) {
            console.log(`[archiver] Moved ${result.rows.length} resolved report(s) into history.`);
        }
    } catch (err) {
        console.log('[archiver] Failed to run archiving check:', err.message);
    }
}

setInterval(archiveOldResolvedReports, ARCHIVE_CHECK_INTERVAL_MS);
archiveOldResolvedReports();

app.post("/submit-report", requireAuth, async (req, res) => {
    const { user_id, description, image, location } = req.body;

    if (!user_id || !description) {
        return res.status(400).json({ message: "User ID and description are required" });
    }

    if (req.user.role === "community_member" && req.user.id !== user_id) {
        return res.status(403).json({ message: "You can only submit reports for your own account" });
    }

    const parsedImage = image ? parseImageDataUrl(image) : null;
    if (image && !parsedImage) {
        return res.status(400).json({ message: "Invalid image format. Please attach a JPEG or PNG photo." });
    }

    const newLocation = parseLocation(location);

    if (newLocation && parsedImage) {
        try {
            const candidatesResult = await pool.query(
                `SELECT id, image, location FROM Reports
                 WHERE status != 'Resolved' AND location IS NOT NULL
                 ORDER BY date DESC
                 LIMIT 50`
            );

            const nearbyCandidates = candidatesResult.rows.filter(r => {
                const loc = parseLocation(r.location);
                if (!loc || !r.image) return false;
                const distance = haversineDistance(newLocation.lat, newLocation.lng, loc.lat, loc.lng);
                return distance <= DUPLICATE_RADIUS_METERS;
            }).slice(0, 10);

            console.log(`[duplicate check] Found ${candidatesResult.rows.length} active reports, ${nearbyCandidates.length} within ${DUPLICATE_RADIUS_METERS}m`);

            for (const candidate of nearbyCandidates) {
                const candidateBuffer = await readImage(candidate.image);
                if (!candidateBuffer) {
                    console.log(`[duplicate check] Could not read image for report #${candidate.id}, skipping`);
                    continue;
                }

                const formData = new FormData();
                formData.append('image1', new Blob([parsedImage.buffer]), 'new.jpg');
                formData.append('image2', new Blob([candidateBuffer]), 'existing.jpg');

                const dupRes = await fetch(`${process.env.AI_SERVICE_URL || 'http://localhost:8000'}/check-duplicate`, {
                    method: 'POST',
                    body: formData
                });

                if (dupRes.ok) {
                    const dupData = await dupRes.json();
                    console.log(`[duplicate check] Compared against report #${candidate.id}: is_duplicate=${dupData.is_duplicate}, confidence=${dupData.confidence}`);
                    if (dupData.is_duplicate && dupData.confidence >= 0.7) {
                        return res.status(409).json({
                            message: "This report has been submitted before.",
                            duplicate_of: candidate.id
                        });
                    }
                } else {
                    console.log(`[duplicate check] AI service returned non-OK status ${dupRes.status} for report #${candidate.id}`);
                }
            }
        } catch (err) {
            console.log('[duplicate check] Failed, proceeding with submission:', err.message);
        }
    } else {
        console.log(`[duplicate check] Skipped — newLocation: ${!!newLocation}, image present: ${!!image}`);
    }

    let ai_category = null;
    let ai_confidence = null;

    if (parsedImage) {
        try {
            const formData = new FormData();
            formData.append('image', new Blob([parsedImage.buffer]), 'report.jpg');

            const aiRes = await fetch(`${process.env.AI_SERVICE_URL || 'http://localhost:8000'}/classify`, {
                method: 'POST',
                body: formData
            });

            if (aiRes.ok) {
                const aiData = await aiRes.json();
                ai_category = aiData.category;
                ai_confidence = aiData.confidence;
            } else {
                console.log('AI service responded with status:', aiRes.status);
            }
        } catch (err) {
            console.log('AI service unreachable, submitting report without classification:', err.message);
        }
    }

    let imageUrl = null;

    try {
        if (parsedImage) {
            imageUrl = await saveImage(parsedImage, "reports");
        }

        const insertResult = await pool.query(
            `INSERT INTO Reports (user_id, description, image, location, ai_category, ai_confidence)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id`,
            [user_id, description, imageUrl, location || null, ai_category, ai_confidence]
        );

        const newReportId = insertResult.rows[0].id;

        const submitterName = await getUserDisplayName(user_id);
        await createNotification(
            "report",
            newReportId,
            `New report from ${submitterName}`,
            truncate(description, 120)
        );

        res.json({
            message: "Report submitted successfully",
            ai_category,
            ai_confidence
        });

    } catch (err) {
        console.log(err);
        // Don't leave an orphaned file behind if the report wasn't saved.
        if (imageUrl) await deleteImage(imageUrl);
        res.status(500).json({ message: "Could not submit your report right now. Please try again later." });
    }
});

// ======================================
// GET USER REPORTS API
// ======================================
app.get("/my-reports/:user_id", requireAuth, async (req, res) => {
    const { user_id } = req.params;
    const showArchived = req.query.archived === 'true';

    if (req.user.role === "community_member" && String(req.user.id) !== String(user_id)) {
        return res.status(403).json({ message: "You can only view your own reports" });
    }

    try {
        const result = await pool.query(
            `SELECT id, description, image, location, status, date, resolved_at, ai_category, ai_confidence,
                    after_image, after_image_at
             FROM Reports
             WHERE user_id = $1 AND is_archived = $2
             ORDER BY date DESC`,
            [user_id, showArchived]
        );

        res.json(result.rows);

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

// ======================================
// DELETE ONE OF MY REPORTS
// A resident can withdraw their own report only while it is still
// "Received" — once the municipality starts working on it, the record
// belongs to the municipality and can't be removed by the resident.
// ======================================
app.delete("/reports/:id", requireAuth, async (req, res) => {
    const { id } = req.params;
    const client = await pool.connect();

    try {
        const result = await client.query(
            "SELECT user_id, status, image, after_image FROM Reports WHERE id = $1",
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "Report not found" });
        }

        const report = result.rows[0];

        if (String(report.user_id) !== String(req.user.id)) {
            return res.status(403).json({ message: "You can only delete your own reports" });
        }

        if (report.status !== "Received") {
            return res.status(409).json({
                message: `This report is already "${report.status}" and the municipality is working on it, so it can no longer be deleted.`
            });
        }

        await client.query("BEGIN");
        await client.query(
            "DELETE FROM Notifications WHERE related_id = $1 AND type IN ('report', 'report_status')",
            [id]
        );
        await client.query("DELETE FROM Reports WHERE id = $1", [id]);
        await client.query("COMMIT");

        await deleteImage(report.image);
        await deleteImage(report.after_image);

        res.json({ message: "Report deleted" });

    } catch (err) {
        await client.query("ROLLBACK").catch(() => {});
        console.log(err);
        res.status(500).json({ message: "Server error" });
    } finally {
        client.release();
    }
});

// ======================================
// GET ALL REPORTS (Municipality Dashboard)
// ======================================
app.get("/reports", requireAuth, requireRole("municipal_worker", "supervisor"), async (req, res) => {
    const { status, search, category } = req.query;
    const showArchived = req.query.archived === 'true';

    let query = `
        SELECT r.id, r.description, r.image, r.location, r.status, r.date, r.ai_category, r.ai_confidence,
               u.first_name, u.last_name, u.email
        FROM Reports r
        JOIN Users u ON r.user_id = u.id
    `;
    const conditions = [`r.is_archived = $1`];
    const values = [showArchived];

    if (status) {
        values.push(status);
        conditions.push(`r.status = $${values.length}`);
    }
    if (search) {
        values.push(`%${search}%`);
        conditions.push(`r.description ILIKE $${values.length}`);
    }
    if (category) {
        values.push(category);
        conditions.push(`r.ai_category = $${values.length}`);
    }
    query += " WHERE " + conditions.join(" AND ");
    query += " ORDER BY r.date DESC";

    // Optional ?limit=N (e.g. the dashboard's "recent reports" list)
    const limit = parseInt(req.query.limit, 10);
    if (Number.isInteger(limit) && limit > 0) {
        values.push(Math.min(limit, 100));
        query += ` LIMIT $${values.length}`;
    }

    try {
        const result = await pool.query(query, values);
        res.json(result.rows);
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

// ======================================
// REPORT STATISTICS (Municipal dashboard summary cards)
// Must be registered before /reports/:id, or "stats" would be read as an id.
// Resolved counts include archived reports, so the totals reflect all
// work ever done — not just what's still on the active list.
// ======================================
app.get("/reports/stats", requireAuth, requireRole("municipal_worker", "supervisor"), async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT COUNT(*)                                                    AS total,
                    COUNT(*) FILTER (WHERE status = 'Received')                 AS received,
                    COUNT(*) FILTER (WHERE status = 'Under Review')             AS under_review,
                    COUNT(*) FILTER (WHERE status = 'Assigned')                 AS assigned,
                    COUNT(*) FILTER (WHERE status = 'Resolved')                 AS resolved,
                    COUNT(*) FILTER (WHERE date >= NOW() - INTERVAL '7 days')   AS new_this_week
             FROM Reports`
        );

        const row = result.rows[0];
        const n = key => parseInt(row[key], 10) || 0;

        res.json({
            total: n("total"),
            received: n("received"),
            under_review: n("under_review"),
            assigned: n("assigned"),
            in_progress: n("under_review") + n("assigned"),
            resolved: n("resolved"),
            new_this_week: n("new_this_week")
        });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

// ======================================
// GET SINGLE REPORT
// ======================================
app.get("/reports/:id", requireAuth, requireRole("municipal_worker", "supervisor"), async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT r.id, r.description, r.image, r.location, r.status, r.date, r.ai_category, r.ai_confidence,
                    r.after_image, r.after_image_at, r.resolved_at, r.is_archived,
                    u.first_name, u.last_name, u.email
             FROM Reports r
             JOIN Users u ON r.user_id = u.id
             WHERE r.id = $1`,
            [req.params.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "Report not found" });
        }

        res.json(result.rows[0]);
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

// ======================================
// UPDATE REPORT STATUS
// ======================================
function statusChangeNotification(status, description) {
    const issue = truncate(description, 80);
    switch (status) {
        case "Under Review":
            return { title: "Your report is under review", message: `The municipality is reviewing your report: "${issue}"` };
        case "Assigned":
            return { title: "A repair team has been assigned", message: `Your report has been assigned for repair: "${issue}"` };
        case "Resolved":
            return { title: "Your report has been resolved", message: `The municipality marked this issue as fixed: "${issue}". It will move to your History within 24 hours.` };
        default:
            return { title: `Your report status changed to ${status}`, message: `"${issue}"` };
    }
}

app.patch("/reports/:id", requireAuth, requireRole("municipal_worker", "supervisor"), async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    const validStatuses = ["Received", "Under Review", "Assigned", "Resolved"];
    if (!validStatuses.includes(status)) {
        return res.status(400).json({ message: "Invalid status value" });
    }

    try {
        const existing = await pool.query(
            "SELECT status FROM Reports WHERE id = $1",
            [id]
        );

        if (existing.rows.length === 0) {
            return res.status(404).json({ message: "Report not found" });
        }

        const oldStatus = existing.rows[0].status;

        // Re-saving "Resolved" keeps the original resolved_at, so the
        // 24h auto-archive timer isn't restarted every time.
        // ($3 is a separate boolean — reusing $1 as both varchar and text
        // makes Postgres fail with "inconsistent types deduced for parameter".)
        const result = await pool.query(
            `UPDATE Reports
             SET status = $1,
                 resolved_at = CASE
                     WHEN $3 THEN COALESCE(resolved_at, NOW())
                     ELSE NULL
                 END
             WHERE id = $2
             RETURNING id, user_id, description, status`,
            [status, id, status === "Resolved"]
        );

        const report = result.rows[0];

        if (oldStatus !== status) {
            const { title, message } = statusChangeNotification(status, report.description);
            await createNotification("report_status", report.id, title, message, report.user_id);
        }

        res.json({ message: "Status updated", report: { id: report.id, description: report.description, status: report.status } });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

// ======================================
// UPLOAD AFTER-REPAIR PHOTO
// Staff upload a photo of the completed repair. This marks the report
// Resolved (starting the 24h move to History) and notifies the resident.
// Uploading again replaces the previous photo.
// ======================================
app.post("/reports/:id/after-image", requireAuth, requireRole("municipal_worker", "supervisor"), async (req, res) => {
    const { id } = req.params;

    const parsedImage = parseImageDataUrl(req.body.image);
    if (!parsedImage) {
        return res.status(400).json({ message: "Please attach a JPEG or PNG photo of the completed repair." });
    }

    let newImageUrl = null;

    try {
        const existing = await pool.query(
            "SELECT status, after_image, is_archived FROM Reports WHERE id = $1",
            [id]
        );

        if (existing.rows.length === 0) {
            return res.status(404).json({ message: "Report not found" });
        }

        const before = existing.rows[0];
        if (before.is_archived) {
            return res.status(409).json({ message: "This report has already been archived and can't be changed." });
        }

        newImageUrl = await saveImage(parsedImage, "repairs");

        const result = await pool.query(
            `UPDATE Reports
             SET after_image = $1,
                 after_image_at = NOW(),
                 status = 'Resolved',
                 resolved_at = COALESCE(resolved_at, NOW())
             WHERE id = $2
             RETURNING id, user_id, description, status, after_image, after_image_at`,
            [newImageUrl, id]
        );
        newImageUrl = null; // now referenced by the DB — must not be cleaned up below

        const report = result.rows[0];

        if (before.after_image) {
            await deleteImage(before.after_image);
        }

        if (before.status !== "Resolved") {
            await createNotification(
                "report_status",
                report.id,
                "Your report has been fixed",
                `The municipality uploaded a photo of the completed repair: "${truncate(report.description, 80)}". It will move to your History within 24 hours.`,
                report.user_id
            );
        }

        res.json({
            message: before.status === "Resolved"
                ? "After-repair photo updated."
                : "After-repair photo saved and report marked as Resolved.",
            report: {
                id: report.id,
                status: report.status,
                after_image: report.after_image,
                after_image_at: report.after_image_at
            }
        });

    } catch (err) {
        console.log(err);
        if (newImageUrl) await deleteImage(newImageUrl);
        res.status(500).json({ message: "Server error" });
    }
});

// ======================================
// CREATE STAFF ACCOUNT
// ======================================
function generateTempPassword() {
    const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    const lower = "abcdefghijkmnpqrstuvwxyz";
    const digits = "23456789";
    const symbols = "!@#$%&*";
    const all = upper + lower + digits + symbols;

    let pwd = [
        upper[crypto.randomInt(upper.length)],
        lower[crypto.randomInt(lower.length)],
        digits[crypto.randomInt(digits.length)],
        symbols[crypto.randomInt(symbols.length)],
    ];
    for (let i = pwd.length; i < 12; i++) {
        pwd.push(all[crypto.randomInt(all.length)]);
    }
    for (let i = pwd.length - 1; i > 0; i--) {
        const j = crypto.randomInt(i + 1);
        [pwd[i], pwd[j]] = [pwd[j], pwd[i]];
    }
    return pwd.join("");
}

function escapeEmailHtml(text) {
    return String(text ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

/** Emails a staff member their login email + temporary password. Returns true if sent. */
async function sendStaffCredentialsEmail({ to, firstName, tempPassword, subject, intro }) {
    try {
        await transporter.sendMail({
            from: process.env.SMTP_FROM || '"Community Portal" <no-reply@communityportal.local>',
            to,
            subject,
            html: `
                <div style="font-family:Segoe UI,sans-serif;max-width:500px;margin:auto;">
                    <p>Hi ${escapeEmailHtml(firstName)},</p>
                    <p>${intro}</p>
                    <p><strong>Login email:</strong> ${escapeEmailHtml(to)}<br>
                    <strong>Temporary password:</strong> <code style="font-size:16px;">${escapeEmailHtml(tempPassword)}</code></p>
                    <p>Sign in at <a href="${process.env.APP_URL || 'http://localhost:3000'}/municipal-login.html">${process.env.APP_URL || 'http://localhost:3000'}/municipal-login.html</a>.
                    You'll be asked to choose your own password straight away.</p>
                    <hr style="border:none;border-top:1px solid #e2e8f0;">
                    <p style="font-size:13px;color:#64748b;">If you weren't expecting this, contact your supervisor.</p>
                </div>
            `
        });
        return true;
    } catch (err) {
        console.log(`[staff] Could not email login details to ${to}:`, err.message);
        return false;
    }
}

// ======================================
// STAFF LIST (supervisors)
// ======================================
app.get("/admin/staff", requireAuth, requireRole("supervisor", "admin"), async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, first_name, last_name, email, phone, role, must_change_password
             FROM Users
             WHERE role IN ('municipal_worker', 'supervisor')
             ORDER BY role DESC, first_name, last_name`
        );
        res.json(result.rows);
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

// ======================================
// SUPERVISOR RESETS A STAFF MEMBER'S PASSWORD
// For when a worker can't use "Forgot password" (e.g. the email never
// arrives). Sets a temporary password, forces them to choose a new one at
// next sign-in (must_change_password), and clears any login lock.
// Supervisors can reset municipal workers; resetting a supervisor needs an
// admin, so one supervisor can't take over another's account. Residents
// use the self-service "Forgot password" flow only.
// ======================================
app.post("/admin/staff/:id/reset-password", requireAuth, requireRole("supervisor", "admin"), async (req, res) => {
    const targetId = Number(req.params.id);

    if (targetId === req.user.id) {
        return res.status(400).json({ message: "To change your own password, use “Forgot password” on the sign-in page." });
    }

    try {
        const result = await pool.query(
            "SELECT id, first_name, last_name, email, role FROM Users WHERE id = $1",
            [targetId]
        );
        const target = result.rows[0];

        if (!target || !["municipal_worker", "supervisor"].includes(target.role)) {
            return res.status(404).json({ message: "Staff member not found" });
        }
        if (target.role === "supervisor" && req.user.role !== "admin") {
            return res.status(403).json({ message: "Only an administrator can reset a supervisor's password." });
        }

        const tempPassword = generateTempPassword();
        const passwordHash = await bcrypt.hash(tempPassword, SALT_ROUNDS);

        await pool.query(
            `UPDATE Users
             SET password = $1, must_change_password = true,
                 reset_token = NULL, reset_token_expiry = NULL
             WHERE id = $2`,
            [passwordHash, target.id]
        );
        await loginSecurity.clear(`login:${String(target.email).trim().toLowerCase()}`);

        const emailSent = await sendStaffCredentialsEmail({
            to: target.email,
            firstName: target.first_name,
            tempPassword,
            subject: "Your CIRIS Municipal Portal password has been reset",
            intro: "Your supervisor has reset your CIRIS Municipal Portal password."
        });

        console.log(`[staff] User #${req.user.id} reset the password of staff member #${target.id}`);

        res.json({
            message: emailSent
                ? `Password reset. ${target.first_name} has been emailed a temporary password.`
                : `Password reset, but the email could not be sent — give ${target.first_name} the temporary password below.`,
            temp_password: tempPassword,
            email_sent: emailSent
        });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

app.post("/admin/create-staff", requireAuth, requireRole("supervisor", "admin"), async (req, res) => {
    const { first_name, last_name, email, phone, role } = req.body;

    const allowedStaffRoles = ["municipal_worker", "supervisor"];
    if (!allowedStaffRoles.includes(role)) {
        return res.status(400).json({ message: "Role must be municipal_worker or supervisor" });
    }
    if (!first_name || !last_name || !email || !phone) {
        return res.status(400).json({ message: "All fields are required" });
    }

    const phoneRegex = /^(\+27|0)[6-8][0-9]{8}$/;
    if (!phoneRegex.test(phone)) {
        return res.status(400).json({ message: "Please enter a valid South African phone number" });
    }

    try {
        const existing = await pool.query("SELECT id FROM Users WHERE email = $1", [email]);
        if (existing.rows.length > 0) {
            return res.status(400).json({ message: "Email already exists" });
        }

        const tempPassword = generateTempPassword();
        const passwordHash = await bcrypt.hash(tempPassword, SALT_ROUNDS);

        const result = await pool.query(
            `INSERT INTO Users (first_name, last_name, email, phone, password, role, must_change_password)
             VALUES ($1, $2, $3, $4, $5, $6, true)
             RETURNING id, first_name, last_name, email, role`,
            [first_name, last_name, email, phone, passwordHash, role]
        );

        const emailSent = await sendStaffCredentialsEmail({
            to: email,
            firstName: first_name,
            tempPassword,
            subject: "Your CIRIS Municipal Portal account has been created",
            intro: "A municipal staff account has been created for you on the CIRIS platform."
        });

        // The temporary password is returned once so the supervisor can hand
        // it over in person if the email doesn't arrive. It is never stored
        // in plain text and can't be retrieved again.
        res.json({
            message: emailSent
                ? "Staff account created and login details emailed."
                : "Staff account created, but the email could not be sent — give them the temporary password below.",
            user: result.rows[0],
            temp_password: tempPassword,
            email_sent: emailSent
        });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

// ======================================
// GET USER PROFILE
// ======================================
app.get("/user/:id", requireAuth, async (req, res) => {
    const isStaff = ["municipal_worker", "supervisor", "admin"].includes(req.user.role);
    if (!isStaff && String(req.user.id) !== String(req.params.id)) {
        return res.status(403).json({ message: "You can only view your own profile" });
    }

    try {
        const result = await pool.query(
            "SELECT id, first_name, last_name, email, phone, profile_picture FROM Users WHERE id = $1",
            [req.params.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }
        res.json(result.rows[0]);
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

// ======================================
// SECURITY NOTIFICATION EMAILS
// ======================================
async function sendSecurityEmail(toEmail, subject, htmlBody) {
    try {
        await transporter.sendMail({
            from: process.env.SMTP_FROM || '"Community Portal" <no-reply@communityportal.local>',
            to: toEmail,
            subject: subject,
            html: htmlBody
        });
        console.log(`Security email sent to ${toEmail}`);
    } catch (err) {
        console.log("Failed to send security email:", err.message);
    }
}

// ======================================
// UPDATE PROFILE
// ======================================
app.post("/update-profile", requireAuth, async (req, res) => {
    const { id, phone, profile_picture } = req.body;
    if (!id) return res.status(400).json({ message: "User ID is required" });

    if (String(req.user.id) !== String(id)) {
        return res.status(403).json({ message: "You can only update your own profile" });
    }

    const phoneRegex = /^(\+27|0)[6-8][0-9]{8}$/;
    if (phone && !phoneRegex.test(phone)) {
        return res.status(400).json({ message: "Invalid South African phone number" });
    }

    // profile_picture can be:
    //   undefined          -> leave the picture alone
    //   null / ""          -> remove the picture
    //   a data URL         -> new upload, saved to /uploads/profiles
    //   the current URL    -> unchanged (the profile page re-sends it)
    const parsedPicture = profile_picture ? parseImageDataUrl(profile_picture) : null;
    if (profile_picture && !parsedPicture && !isStoredImageUrl(profile_picture)) {
        return res.status(400).json({ message: "Invalid profile picture format" });
    }

    let newPictureUrl = null;

    try {
        const oldResult = await pool.query(
            "SELECT email, phone, profile_picture FROM Users WHERE id = $1",
            [id]
        );

        if (oldResult.rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        const oldPhone = oldResult.rows[0].phone;
        const oldPicture = oldResult.rows[0].profile_picture;

        if (profile_picture && !parsedPicture && profile_picture !== oldPicture) {
            return res.status(400).json({ message: "Invalid profile picture format" });
        }

        const fields = ["phone = $1"];
        const values = [phone || null];
        let paramIndex = 2;

        let pictureChanged = false;
        if (parsedPicture) {
            newPictureUrl = await saveImage(parsedPicture, "profiles");
            fields.push(`profile_picture = $${paramIndex}`);
            values.push(newPictureUrl);
            paramIndex++;
            pictureChanged = true;
        } else if (profile_picture === null || profile_picture === "") {
            fields.push(`profile_picture = $${paramIndex}`);
            values.push(null);
            paramIndex++;
            pictureChanged = true;
        }

        values.push(id);
        await pool.query(
            `UPDATE Users SET ${fields.join(", ")} WHERE id = $${paramIndex}`,
            values
        );
        newPictureUrl = null; // now referenced by the DB — must not be cleaned up below

        if (pictureChanged && oldPicture) {
            await deleteImage(oldPicture);
        }

        if (oldPhone !== phone) {
            const timeStr = new Date().toLocaleString('en-ZA', { timeZone: 'Africa/Johannesburg' });
            await sendSecurityEmail(
                oldResult.rows[0].email,
                "Security Alert: Profile Information Changed",
                `
                <div style="font-family:Segoe UI,sans-serif;max-width:500px;margin:auto;">
                    <h2 style="color:#1e3c72;">Security Alert</h2>
                    <p>Your <strong>phone number</strong> was just updated on your Community Portal account.</p>
                    <p><strong>Time:</strong> ${timeStr}</p>
                    <hr style="border:none;border-top:1px solid #e2e8f0;">
                    <p style="font-size:13px;color:#64748b;">
                        If you did not make this change, please contact support immediately or reset your password.
                    </p>
                </div>
                `
            );
        }

        const result = await pool.query(
            "SELECT id, first_name, last_name, email, phone, profile_picture FROM Users WHERE id = $1",
            [id]
        );

        res.json({ message: "Profile updated", user: result.rows[0] });

    } catch (err) {
        console.log(err);
        if (newPictureUrl) await deleteImage(newPictureUrl);
        res.status(500).json({ message: "Server error" });
    }
});

// ======================================
// FEEDBACK
// ======================================
app.post("/feedback", requireAuth, async (req, res) => {
    const message = (req.body.message || "").trim();
    if (!message) {
        return res.status(400).json({ message: "Please write a message before sending." });
    }
    if (message.length > 2000) {
        return res.status(400).json({ message: "Message is too long (max 2000 characters)." });
    }

    try {
        const insertResult = await pool.query(
            "INSERT INTO Feedback (user_id, message) VALUES ($1, $2) RETURNING id",
            [req.user.id, message]
        );

        const submitterName = await getUserDisplayName(req.user.id);
        await createNotification(
            "feedback",
            insertResult.rows[0].id,
            `New feedback from ${submitterName}`,
            truncate(message, 120)
        );

        res.json({ message: "Feedback sent. Thank you!" });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Could not send feedback. Please try again." });
    }
});

app.get("/feedback/mine", requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, message, date, reply_message, reply_date
             FROM Feedback
             WHERE user_id = $1
             ORDER BY date DESC`,
            [req.user.id]
        );
        res.json(result.rows);
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

app.get("/feedback", requireAuth, requireRole("municipal_worker", "supervisor"), async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT f.id, f.message, f.date, f.is_read,
                    f.reply_message, f.reply_date,
                    u.first_name, u.last_name, u.email,
                    ru.first_name AS replied_by_first_name, ru.last_name AS replied_by_last_name
             FROM Feedback f
             JOIN Users u ON f.user_id = u.id
             LEFT JOIN Users ru ON f.replied_by = ru.id
             ORDER BY f.date DESC`
        );
        res.json(result.rows);
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

app.get("/feedback/unread-count", requireAuth, requireRole("municipal_worker", "supervisor"), async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT COUNT(*) FROM Feedback WHERE is_read = false"
        );
        res.json({ count: parseInt(result.rows[0].count, 10) });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

app.patch("/feedback/:id/read", requireAuth, requireRole("municipal_worker", "supervisor"), async (req, res) => {
    try {
        await pool.query(
            "UPDATE Feedback SET is_read = true WHERE id = $1",
            [req.params.id]
        );
        res.json({ message: "Marked as read" });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

app.patch("/feedback/:id/reply", requireAuth, requireRole("municipal_worker", "supervisor"), async (req, res) => {
    const { id } = req.params;
    const reply = (req.body.reply || "").trim();

    if (!reply) {
        return res.status(400).json({ message: "Please write a reply before sending." });
    }
    if (reply.length > 2000) {
        return res.status(400).json({ message: "Reply is too long (max 2000 characters)." });
    }

    try {
        const result = await pool.query(
            `UPDATE Feedback
             SET reply_message = $1, reply_date = NOW(), replied_by = $2
             WHERE id = $3
             RETURNING id, user_id`,
            [reply, req.user.id, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "Feedback not found" });
        }

        const feedback = result.rows[0];

        await createNotification(
            "feedback_reply",
            feedback.id,
            "The municipality replied to your feedback",
            truncate(reply, 120),
            feedback.user_id
        );

        res.json({ message: "Reply sent" });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

// ======================================
// NOTIFICATIONS — municipal staff inbox
// ======================================
app.get("/notifications", requireAuth, requireRole("municipal_worker", "supervisor"), async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, type, related_id, title, message, is_read, date
             FROM Notifications
             WHERE user_id IS NULL
             ORDER BY date DESC`
        );
        res.json(result.rows);
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

app.get("/notifications/unread-count", requireAuth, requireRole("municipal_worker", "supervisor"), async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT COUNT(*) FROM Notifications WHERE user_id IS NULL AND is_read = false"
        );
        res.json({ count: parseInt(result.rows[0].count, 10) });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

app.patch("/notifications/:id/read", requireAuth, requireRole("municipal_worker", "supervisor"), async (req, res) => {
    try {
        const result = await pool.query(
            "UPDATE Notifications SET is_read = true WHERE id = $1 AND user_id IS NULL RETURNING id",
            [req.params.id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ message: "Notification not found" });
        }
        res.json({ message: "Marked as read" });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

app.patch("/notifications/mark-all-read", requireAuth, requireRole("municipal_worker", "supervisor"), async (req, res) => {
    try {
        await pool.query(
            "UPDATE Notifications SET is_read = true WHERE user_id IS NULL AND is_read = false"
        );
        res.json({ message: "All notifications marked as read" });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

// ======================================
// NOTIFICATIONS — personal inbox for community members
// ======================================

app.get("/my-notifications", requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, type, related_id, title, message, is_read, date
             FROM Notifications
             WHERE user_id = $1
             ORDER BY date DESC`,
            [req.user.id]
        );
        res.json(result.rows);
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

app.get("/my-notifications/unread-count", requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT COUNT(*) FROM Notifications WHERE user_id = $1 AND is_read = false",
            [req.user.id]
        );
        res.json({ count: parseInt(result.rows[0].count, 10) });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

app.patch("/my-notifications/:id/read", requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            "UPDATE Notifications SET is_read = true WHERE id = $1 AND user_id = $2 RETURNING id",
            [req.params.id, req.user.id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ message: "Notification not found" });
        }
        res.json({ message: "Marked as read" });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

app.patch("/my-notifications/mark-all-read", requireAuth, async (req, res) => {
    try {
        await pool.query(
            "UPDATE Notifications SET is_read = true WHERE user_id = $1 AND is_read = false",
            [req.user.id]
        );
        res.json({ message: "All notifications marked as read" });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

function isValidEmailFormat(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ======================================
// REQUEST EMAIL CHANGE
// ======================================
app.post("/profile/request-email-change", requireAuth, async (req, res) => {
    const email = (req.body.newEmail || "").trim().toLowerCase();

    if (!isValidEmailFormat(email)) {
        return res.status(400).json({ message: "Please enter a valid email address." });
    }

    const allowedDomains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com'];
    const domain = email.split('@')[1];
    if (!allowedDomains.includes(domain)) {
        return res.status(400).json({ message: "Please use a personal email from an allowed domain (gmail.com, yahoo.com, outlook.com, hotmail.com, icloud.com)" });
    }

    try {
        const taken = await pool.query(
            "SELECT id FROM Users WHERE email = $1 AND id != $2",
            [email, req.user.id]
        );
        if (taken.rows.length > 0) {
            return res.status(400).json({ message: "That email is already in use by another account." });
        }

        // A fresh code gets a fresh set of guesses
        await loginSecurity.clear(`emailchange:${req.user.id}`);

        const code = generateOtp();
        const expiry = new Date(Date.now() + RESET_CODE_TTL_MINUTES * 60 * 1000);

        await pool.query(
            `UPDATE Users
             SET pending_email = $1, pending_email_token = $2, pending_email_token_expiry = $3
             WHERE id = $4`,
            [email, hashOtp(code), expiry, req.user.id]
        );

        await transporter.sendMail({
            from: process.env.SMTP_FROM || '"Community Portal" <no-reply@communityportal.local>',
            to: email,
            subject: "Confirm your new email address",
            html: `
                <p>Use this code in the app to confirm this email on your Community Portal account:</p>
                <p style="font-size: 28px; font-weight: bold; letter-spacing: 4px;">${code}</p>
                <p>This code expires in ${RESET_CODE_TTL_MINUTES} minutes. If you didn't request this, you can ignore this email.</p>
            `
        });

        res.json({ message: "Verification code sent to the new email address." });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Could not send verification code. Please check the address and try again." });
    }
});

// ======================================
// CONFIRM EMAIL CHANGE
// ======================================
app.post("/profile/confirm-email-change", requireAuth, async (req, res) => {
    const { code } = req.body;
    if (!code) return res.status(400).json({ message: "Verification code is required." });

    try {
        const result = await pool.query(
            "SELECT email, pending_email, pending_email_token, pending_email_token_expiry FROM Users WHERE id = $1",
            [req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "User not found." });
        }

        const user = result.rows[0];
        const notExpired = user.pending_email_token_expiry && new Date(user.pending_email_token_expiry) > new Date();

        if (!user.pending_email || !user.pending_email_token || !notExpired) {
            return res.status(400).json({ message: "Invalid or expired code. Please request a new one." });
        }

        // Same guess limit as password-reset codes
        const changeKey = `emailchange:${req.user.id}`;
        if (user.pending_email_token !== hashOtp(String(code))) {
            const attempt = await loginSecurity.recordFailure(changeKey, { limit: CODE_MAX_FAILURES });
            if (attempt.limitReached) {
                await pool.query(
                    `UPDATE Users
                     SET pending_email = NULL, pending_email_token = NULL, pending_email_token_expiry = NULL
                     WHERE id = $1`,
                    [req.user.id]
                );
                return res.status(400).json({ message: "Too many incorrect codes. This code has been cancelled — please request a new one." });
            }
            const left = attempt.attemptsLeft;
            return res.status(400).json({ message: `Incorrect code. ${left} attempt${left === 1 ? "" : "s"} left.` });
        }
        await loginSecurity.clear(changeKey);

        const oldEmail = user.email;
        const newEmail = user.pending_email;

        await pool.query(
            `UPDATE Users
             SET email = $1, pending_email = NULL, pending_email_token = NULL, pending_email_token_expiry = NULL
             WHERE id = $2`,
            [newEmail, req.user.id]
        );

        const timeStr = new Date().toLocaleString('en-ZA', { timeZone: 'Africa/Johannesburg' });
        await sendSecurityEmail(
            oldEmail,
            "Your Email Address Has Been Changed",
            `
            <div style="font-family:Segoe UI,sans-serif;max-width:500px;margin:auto;">
                <h2 style="color:#1e3c72;">Email Changed</h2>
                <p>Your Community Portal login email was changed to <strong>${newEmail}</strong>.</p>
                <p><strong>Time:</strong> ${timeStr}</p>
                <hr style="border:none;border-top:1px solid #e2e8f0;">
                <p style="font-size:13px;color:#64748b;">
                    If you did not make this change, please contact support immediately.
                </p>
            </div>
            `
        );

        const updated = await pool.query(
            "SELECT id, first_name, last_name, email, phone, profile_picture FROM Users WHERE id = $1",
            [req.user.id]
        );

        res.json({ message: "Email updated successfully.", user: updated.rows[0] });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Could not confirm email change. Please try again." });
    }
});

// ======================================
// CHANGE PASSWORD
// ======================================
app.post("/change-password", requireAuth, async (req, res) => {
    const { id, currentPassword, newPassword } = req.body;
    if (!id || !currentPassword || !newPassword) {
        return res.status(400).json({ message: "All fields are required" });
    }

    if (String(req.user.id) !== String(id)) {
        return res.status(403).json({ message: "You can only change your own password" });
    }

    const strength = validatePasswordStrength(newPassword);
    if (!strength.valid) {
        return res.status(400).json({ message: strength.message });
    }

    try {
        const result = await pool.query(
            "SELECT email, password FROM Users WHERE id = $1",
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        const user = result.rows[0];
        const match = await bcrypt.compare(currentPassword, user.password);
        if (!match) {
            return res.status(401).json({ message: "Current password is incorrect" });
        }

        const hash = await bcrypt.hash(newPassword, SALT_ROUNDS);
        await pool.query(
            "UPDATE Users SET password = $1, must_change_password = false WHERE id = $2",
            [hash, id]
        );

        await sendSecurityEmail(
            user.email,
            "Your Password Has Been Changed",
            `
            <div style="font-family:Segoe UI,sans-serif;max-width:500px;margin:auto;">
                <h2 style="color:#1e3c72;">Password Changed</h2>
                <p>Your Community Portal password was just updated.</p>
                <p><strong>Time:</strong> ${new Date().toLocaleString('en-ZA', { timeZone: 'Africa/Johannesburg' })}</p>
                <hr style="border:none;border-top:1px solid #e2e8f0;">
                <p style="font-size:13px;color:#64748b;">
                    If you did not make this change, contact support immediately.
                </p>
            </div>
            `
        );

        res.json({ message: "Password changed successfully" });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

// Fallback: send index.html for any non-API route so the frontend's
// client-side navigation / direct links work (safe no-op if you don't
// have an index.html in /public).
app.get(/^(?!\/(register|login|forgot-password|verify-code|reset-password|submit-report|my-reports|reports|admin|user|update-profile|feedback|notifications|my-notifications|profile|change-password|api|uploads)).*/, (req, res, next) => {
    res.sendFile(path.join(__dirname, "public", "index.html"), err => {
        if (err) next();
    });
});

// ======================================
// START SERVER
// ======================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});