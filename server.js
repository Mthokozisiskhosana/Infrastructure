require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const { validatePasswordStrength } = require("./passwordPolicy");

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('.'));

app.get("/", (req, res) => {
    res.json({ message: "Server is running!" });
});

const SALT_ROUNDS = 12;
const RESET_CODE_TTL_MINUTES = 10;

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
const pool = new Pool({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT) || 5432,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    max: 10,
    idleTimeoutMillis: 30000
});

pool.connect()
    .then(client => {
        console.log("✅ Connected to PostgreSQL");
        client.release();
    })
    .catch(err => console.log("❌ DB Connection Failed:", err));

// ======================================
// EMAIL TRANSPORT
// ======================================
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: false,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

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
// userId is optional: leave it null for a staff-wide notification
// (new report / new feedback). Pass a specific user's id to create a
// *personal* notification only that person can see — e.g. "the
// municipality replied to your feedback".
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
app.post("/register", async (req, res) => {
    const { first_name, last_name, email, phone, password } = req.body;

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
            `INSERT INTO Users (first_name, last_name, email, phone, password, role)
             VALUES ($1, $2, $3, $4, $5, 'community_member')`,
            [first_name, last_name, email, phone, passwordHash]
        );

        res.json({ message: "User registered successfully" });

    } catch (err) {
        console.log("FULL ERROR:", err);
        res.status(500).json({ message: err.message });
    }
});

// ======================================
// LOGIN API
// ======================================
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "Email and password are required" });
    }

    try {
        const result = await pool.query(
            `SELECT id, first_name, last_name, email, phone, password, role, must_change_password
             FROM Users
             WHERE email = $1`,
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

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
            "SELECT id FROM Users WHERE email = $1",
            [email]
        );

        if (checkUser.rows.length === 0) {
            return res.json(genericResponse);
        }

        const code = generateOtp();
        const expiry = new Date(Date.now() + RESET_CODE_TTL_MINUTES * 60 * 1000);

        await pool.query(
            `UPDATE Users
             SET reset_token = $1, reset_token_expiry = $2
             WHERE email = $3`,
            [hashOtp(code), expiry, email]
        );

        await sendResetCodeEmail(email, code);

        res.json(genericResponse);

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Something went wrong. Please try again later." });
    }
});

// ======================================
// FORGOT PASSWORD — STEP 2
// ======================================
app.post("/verify-code", async (req, res) => {
    const { email, code } = req.body;
    const invalidResponse = { message: "Invalid or expired code." };

    if (!email || !code) {
        return res.status(400).json(invalidResponse);
    }

    try {
        const result = await pool.query(
            `SELECT reset_token, reset_token_expiry
             FROM Users
             WHERE email = $1`,
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(400).json(invalidResponse);
        }

        const user = result.rows[0];
        const validCode = user.reset_token === hashOtp(code);
        const notExpired = user.reset_token_expiry && new Date(user.reset_token_expiry) > new Date();

        if (!validCode || !notExpired) {
            return res.status(400).json(invalidResponse);
        }

        res.json({ message: "Code verified" });

    } catch (err) {
        console.log(err);
        res.status(500).json(invalidResponse);
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
        const result = await pool.query(
            `SELECT id, reset_token, reset_token_expiry
             FROM Users
             WHERE email = $1`,
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({ message: "Invalid or expired code." });
        }

        const user = result.rows[0];
        const validCode = user.reset_token === hashOtp(code);
        const notExpired = user.reset_token_expiry && new Date(user.reset_token_expiry) > new Date();

        if (!validCode || !notExpired) {
            return res.status(400).json({ message: "Invalid or expired code. Please request a new one." });
        }

        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

        await pool.query(
            `UPDATE Users
             SET password = $1, reset_token = NULL, reset_token_expiry = NULL
             WHERE id = $2`,
            [passwordHash, user.id]
        );

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

    const newLocation = parseLocation(location);

    if (newLocation && image) {
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

            const newImageBuffer = Buffer.from(
                image.includes(',') ? image.split(',')[1] : image, 'base64'
            );

            for (const candidate of nearbyCandidates) {
                const candidateBuffer = Buffer.from(
                    candidate.image.includes(',') ? candidate.image.split(',')[1] : candidate.image, 'base64'
                );

                const formData = new FormData();
                formData.append('image1', new Blob([newImageBuffer]), 'new.jpg');
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

    if (image) {
        try {
            const base64Data = image.includes(',') ? image.split(',')[1] : image;
            const buffer = Buffer.from(base64Data, 'base64');

            const formData = new FormData();
            formData.append('image', new Blob([buffer]), 'report.jpg');

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

    try {
        const insertResult = await pool.query(
            `INSERT INTO Reports (user_id, description, image, location, ai_category, ai_confidence)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id`,
            [user_id, description, image || null, location || null, ai_category, ai_confidence]
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
        res.status(500).json({ message: err.message });
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
            `SELECT id, description, image, location, status, date, ai_category, ai_confidence
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
// DELETE ALL USER REPORTS API
// ======================================
app.delete("/clear-reports/:user_id", requireAuth, async (req, res) => {
    const { user_id } = req.params;

    if (req.user.role === "community_member" && String(req.user.id) !== String(user_id)) {
        return res.status(403).json({ message: "You can only clear your own reports" });
    }

    try {
        await pool.query(
            "DELETE FROM Reports WHERE user_id = $1",
            [user_id]
        );

        res.json({ message: "Reports cleared successfully" });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
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

    try {
        const result = await pool.query(query, values);
        res.json(result.rows);
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
app.patch("/reports/:id", requireAuth, requireRole("municipal_worker", "supervisor"), async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    const validStatuses = ["Received", "Under Review", "Assigned", "Resolved"];
    if (!validStatuses.includes(status)) {
        return res.status(400).json({ message: "Invalid status value" });
    }

    try {
        const result = await pool.query(
            `UPDATE Reports
             SET status = $1,
                 resolved_at = CASE WHEN $1 = 'Resolved' THEN NOW() ELSE NULL END
             WHERE id = $2
             RETURNING id, description, status`,
            [status, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "Report not found" });
        }

        res.json({ message: "Status updated", report: result.rows[0] });
    } catch (err) {
        console.log(err);
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

        await transporter.sendMail({
            from: process.env.SMTP_FROM || '"Community Portal" <no-reply@communityportal.local>',
            to: email,
            subject: "Your CIRIS Municipal Portal account has been created",
            html: `
                <p>Hi ${first_name},</p>
                <p>A municipal staff account has been created for you on the CIRIS platform.</p>
                <p><strong>Login email:</strong> ${email}<br>
                <strong>Temporary password:</strong> ${tempPassword}</p>
                <p>Please log in at ${process.env.APP_URL || 'http://localhost:3000'}/municipal-login.html
                and change your password immediately from your profile settings.</p>
            `
        });

        res.json({ message: "Staff account created and credentials emailed", user: result.rows[0] });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

// ======================================
// GET USER PROFILE
// ======================================
app.get("/user/:id", async (req, res) => {
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

    try {
        const oldResult = await pool.query(
            "SELECT email, phone FROM Users WHERE id = $1",
            [id]
        );

        if (oldResult.rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        const oldPhone = oldResult.rows[0].phone;

        const fields = ["phone = $1"];
        const values = [phone || null];
        let paramIndex = 2;

        if (profile_picture !== undefined) {
            fields.push(`profile_picture = $${paramIndex}`);
            values.push(profile_picture);
            paramIndex++;
        }

        values.push(id);
        await pool.query(
            `UPDATE Users SET ${fields.join(", ")} WHERE id = $${paramIndex}`,
            values
        );

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

// Reply to a piece of feedback (municipal staff only). Notifies the
// community member who submitted it via a personal notification.
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
// Every query is scoped to req.user.id, so a citizen can only ever
// see or mark their own notifications (e.g. a reply to their feedback).
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
        const validCode = user.pending_email_token === hashOtp(code);
        const notExpired = user.pending_email_token_expiry && new Date(user.pending_email_token_expiry) > new Date();

        if (!user.pending_email || !validCode || !notExpired) {
            return res.status(400).json({ message: "Invalid or expired code. Please request a new one." });
        }

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

// ======================================
// START SERVER
// ======================================
app.listen(3000, () => {
    console.log("🚀 Server running on http://localhost:3000");
});
