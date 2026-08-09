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
// JWT_SECRET must be set in .env — never hardcode this or commit it.
// Generate one with: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
// ======================================
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = "8h";

if (!JWT_SECRET) {
    console.error("❌ JWT_SECRET is not set in .env — refusing to start.");
    process.exit(1);
}

function generateToken(user) {
    // Keep the payload minimal — id and role are all any route needs
    // to authorize a request. Don't put email/phone/etc in the token.
    return jwt.sign(
        { id: user.id, role: user.role },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
    );
}

// Attaches req.user = { id, role } if the token is valid.
// Responds 401 if missing/invalid, so routes using this never run
// with an unauthenticated request.
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

// Use after requireAuth. Pass the roles allowed to access the route.
// e.g. requireRole("municipal_worker", "supervisor")
function requireRole(...allowedRoles) {
    return (req, res, next) => {
        if (!req.user || !allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ message: "You don't have permission to access this resource" });
        }
        next();
    };
}

// ======================================
// POSTGRESQL CONFIG (from .env — see .env.example)
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
// EMAIL TRANSPORT  (for password reset codes)
// ======================================
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: false, // true for port 465
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

// Generates a random 6-digit code, e.g. "042317"
function generateOtp() {
    return crypto.randomInt(0, 1000000).toString().padStart(6, "0");
}

// We never store the plain code in the DB — only its hash — same
// principle as passwords, in case the DB is ever exposed.
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

    // --- Enforce password strength server-side (source of truth) ---
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

        // --- Hash the password before storing it ---
        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

        // Public registration always creates a community_member.
        // Municipal worker / supervisor / admin accounts are never
        // self-service — they're created directly in the DB by an
        // administrator (see migration_add_role.sql). This prevents
        // anyone from registering themselves as staff via the API.
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
            `SELECT id, first_name, last_name, email, phone, password, role
             FROM Users
             WHERE email = $1`,
            [email]
        );

        // Same generic message whether the email doesn't exist or the
        // password is wrong — don't reveal which one it was.
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
            role: user.role
        });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});


// ======================================
// FORGOT PASSWORD — STEP 1: email a 6-digit code
// Always responds the same way, whether or not the email exists,
// so this endpoint can't be used to find out which emails are registered.
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
            // Don't reveal whether the email exists
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
        // Still don't leak details to the client
        res.status(500).json({ message: "Something went wrong. Please try again later." });
    }
});


// ======================================
// FORGOT PASSWORD — STEP 2: verify the code (before showing the password form)
// This does NOT consume the code — it's just a UX check. The code is
// re-verified for real in step 3, so this endpoint can't be bypassed
// by skipping straight to /reset-password.
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
// FORGOT PASSWORD — STEP 3: set the new password
// Re-checks the code + expiry again here — this is the real gate,
// step 2 was just for UX.
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

        // Update password and invalidate the code (single-use)
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
app.post("/submit-report", requireAuth, async (req, res) => {
    const { user_id, description, image, location } = req.body;

    if (!user_id || !description) {
        return res.status(400).json({ message: "User ID and description are required" });
    }

    // A community member can only submit a report as themselves.
    if (req.user.role === "community_member" && req.user.id !== user_id) {
        return res.status(403).json({ message: "You can only submit reports for your own account" });
    }

    try {
        await pool.query(
            `INSERT INTO Reports (user_id, description, image, location)
             VALUES ($1, $2, $3, $4)`,
            [user_id, description, image || null, location || null]
        );

        res.json({ message: "Report submitted successfully" });

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

    // A community member can only view their own reports.
    // Workers/supervisors are allowed to look up any user's reports
    // (needed for the municipal report-detail screen).
    if (req.user.role === "community_member" && String(req.user.id) !== String(user_id)) {
        return res.status(403).json({ message: "You can only view your own reports" });
    }

    try {
        const result = await pool.query(
            `SELECT id, description, location, status, date
             FROM Reports
             WHERE user_id = $1
             ORDER BY date DESC`,
            [user_id]
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
// Supports optional filters: ?status=Received&search=pothole
// ======================================
app.get("/reports", requireAuth, requireRole("municipal_worker", "supervisor"), async (req, res) => {
    const { status, search } = req.query;

    let query = `
        SELECT r.id, r.description, r.image, r.location, r.status, r.date,
               u.first_name, u.last_name, u.email
        FROM Reports r
        JOIN Users u ON r.user_id = u.id
    `;
    const conditions = [];
    const values = [];

    if (status) {
        values.push(status);
        conditions.push(`r.status = $${values.length}`);
    }
    if (search) {
        values.push(`%${search}%`);
        conditions.push(`r.description ILIKE $${values.length}`);
    }
    if (conditions.length > 0) {
        query += " WHERE " + conditions.join(" AND ");
    }
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
// UPDATE REPORT STATUS (Municipality Dashboard)
// Body: { status: "Under Review" | "Assigned" | "Resolved" | ... }
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
            `UPDATE Reports SET status = $1 WHERE id = $2
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
// CREATE STAFF ACCOUNT (Supervisor/Admin only)
// Generates a random temporary password, emails it to the new
// worker, and requires nothing be typed by the caller except the
// new person's details. Matches SRS 2.3: Supervisors get user
// management privileges.
// ======================================
function generateTempPassword() {
    // 12 chars, guaranteed to include upper/lower/digit/symbol so it
    // passes validatePasswordStrength without a retry loop.
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
    // Shuffle so the guaranteed chars aren't always in the same positions
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
            `INSERT INTO Users (first_name, last_name, email, phone, password, role)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, first_name, last_name, email, role`,
            [first_name, last_name, email, phone, passwordHash, role]
        );

        // Email the temp password directly to the new worker — the
        // supervisor creating the account never sees or handles it.
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
        // Don't throw — we don't want to block the profile update if email fails
    }
}

// ======================================
// UPDATE PROFILE (email, phone, picture)
// Sends security alerts if email/phone changed.
// ======================================
app.post("/update-profile", async (req, res) => {
    const { id, email, phone, profile_picture } = req.body;
    if (!id) return res.status(400).json({ message: "User ID is required" });

    const phoneRegex = /^(\+27|0)[6-8][0-9]{8}$/;
    if (phone && !phoneRegex.test(phone)) {
        return res.status(400).json({ message: "Invalid South African phone number" });
    }

    try {
        // 1. Fetch old data so we know what changed
        const oldResult = await pool.query(
            "SELECT email, phone FROM Users WHERE id = $1",
            [id]
        );

        if (oldResult.rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        const oldData = oldResult.rows[0];
        const oldEmail = oldData.email;
        const oldPhone = oldData.phone;

        // 2. Check email isn't taken by another account
        const check = await pool.query(
            "SELECT id FROM Users WHERE email = $1 AND id != $2",
            [email, id]
        );

        if (check.rows.length > 0) {
            return res.status(400).json({ message: "Email already in use by another account" });
        }

        // 3. Build dynamic query (only touch profile_picture when provided)
        const fields = ["email = $1", "phone = $2"];
        const values = [email, phone || null];
        let paramIndex = 3;

        if (profile_picture !== undefined) {
            fields.push(`profile_picture = $${paramIndex}`);
            values.push(profile_picture);
            paramIndex++;
        }

        values.push(id); // id is always the last parameter
        await pool.query(
            `UPDATE Users SET ${fields.join(", ")} WHERE id = $${paramIndex}`,
            values
        );

        // 4. Send security notifications
        const changedParts = [];
        if (oldEmail !== email) changedParts.push("email address");
        if (oldPhone !== phone) changedParts.push("phone number");

        if (changedParts.length > 0) {
            // Notify OLD email about the change
            const changeText = changedParts.join(" and ");
            const timeStr = new Date().toLocaleString('en-ZA', { timeZone: 'Africa/Johannesburg' });

            await sendSecurityEmail(
                oldEmail,
                "Security Alert: Profile Information Changed",
                `
                <div style="font-family:Segoe UI,sans-serif;max-width:500px;margin:auto;">
                    <h2 style="color:#1e3c72;">Security Alert</h2>
                    <p>Your <strong>${changeText}</strong> was just updated on your Community Portal account.</p>
                    <p><strong>Time:</strong> ${timeStr}</p>
                    <hr style="border:none;border-top:1px solid #e2e8f0;">
                    <p style="font-size:13px;color:#64748b;">
                        If you did not make this change, please contact support immediately or reset your password.
                    </p>
                </div>
                `
            );

            // If email changed, also notify the NEW email
            if (oldEmail !== email) {
                await sendSecurityEmail(
                    email,
                    "Your Email Address Has Been Updated",
                    `
                    <div style="font-family:Segoe UI,sans-serif;max-width:500px;margin:auto;">
                        <h2 style="color:#1e3c72;">Email Updated</h2>
                        <p>Your account email is now <strong>${email}</strong>.</p>
                        <p><strong>Time:</strong> ${timeStr}</p>
                        <hr style="border:none;border-top:1px solid #e2e8f0;">
                        <p style="font-size:13px;color:#64748b;">
                            If you did not request this, please reset your password immediately.
                        </p>
                    </div>
                    `
                );
            }
        }

        // 5. Return updated user
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
// CHANGE PASSWORD
// ======================================
app.post("/change-password", async (req, res) => {
    const { id, currentPassword, newPassword } = req.body;
    if (!id || !currentPassword || !newPassword) {
        return res.status(400).json({ message: "All fields are required" });
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
            "UPDATE Users SET password = $1 WHERE id = $2",
            [hash, id]
        );

        // Notify user that password was changed
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
