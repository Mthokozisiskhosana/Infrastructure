require("dotenv").config();
const express = require("express");
const sql = require("mssql");
const cors = require("cors");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const { validatePasswordStrength } = require("./passwordPolicy");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

app.get("/", (req, res) => {
    res.json({ message: "Server is running!" });
});

const SALT_ROUNDS = 12;
const RESET_CODE_TTL_MINUTES = 10;

// ======================================
// SQL SERVER CONFIG  (now from .env — see .env.example)
// ======================================
const dbConfig = {
    server: process.env.DB_SERVER,
    database: process.env.DB_NAME,
    port: Number(process.env.DB_PORT) || 1433,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    options: {
        trustServerCertificate: true,
        enableArithAbort: true
    },
    pool: {
        max: 10,
        min: 0,
        idleTimeoutMillis: 30000
    }
};

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
// CONNECT TO DATABASE
// ======================================
sql.connect(dbConfig)
    .then(() => console.log("✅ Connected to SQL Server"))
    .catch(err => console.log("❌ DB Connection Failed:", err));


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
        const pool = await sql.connect(dbConfig);

        const checkUser = await pool.request()
            .input("email", sql.VarChar, email)
            .query("SELECT * FROM Users WHERE email = @email");

        if (checkUser.recordset.length > 0) {
            return res.status(400).json({ message: "Email already exists" });
        }

        // --- Hash the password before storing it ---
        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

        await pool.request()
            .input("first_name", sql.VarChar, first_name)
            .input("last_name", sql.VarChar, last_name)
            .input("email", sql.VarChar, email)
            .input("phone", sql.VarChar, phone)
            .input("password", sql.VarChar, passwordHash)
            .query(`
                INSERT INTO Users (first_name, last_name, email, phone, password)
                VALUES (@first_name, @last_name, @email, @phone, @password)
            `);

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

    const allowedDomains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com'];
    const emailDomain = (email || "").split('@')[1];

    if (!emailDomain || !allowedDomains.includes(emailDomain.toLowerCase())) {
        return res.status(400).json({ message: "Please use a personal email from an allowed domain (gmail.com, yahoo.com, outlook.com, hotmail.com, icloud.com)" });
    }

    try {
        const pool = await sql.connect(dbConfig);

        const result = await pool.request()
            .input("email", sql.VarChar, email)
            .query(`
                SELECT id, first_name, last_name, email, phone, password
                FROM Users
                WHERE email = @email
            `);

        // Same generic message whether the email doesn't exist or the
        // password is wrong — don't reveal which one it was.
        if (result.recordset.length === 0) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        const user = result.recordset[0];
        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        res.json({
            id: user.id,
            first_name: user.first_name,
            last_name: user.last_name,
            email: user.email,
            phone: user.phone
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
        const pool = await sql.connect(dbConfig);

        const checkUser = await pool.request()
            .input("email", sql.VarChar, email)
            .query("SELECT id FROM Users WHERE email = @email");

        if (checkUser.recordset.length === 0) {
            // Don't reveal whether the email exists
            return res.json(genericResponse);
        }

        const code = generateOtp();
        const expiry = new Date(Date.now() + RESET_CODE_TTL_MINUTES * 60 * 1000);

        await pool.request()
            .input("email", sql.VarChar, email)
            .input("codeHash", sql.VarChar, hashOtp(code))
            .input("expiry", sql.DateTime, expiry)
            .query(`
                UPDATE Users
                SET reset_token = @codeHash, reset_token_expiry = @expiry
                WHERE email = @email
            `);

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
        const pool = await sql.connect(dbConfig);

        const result = await pool.request()
            .input("email", sql.VarChar, email)
            .query(`
                SELECT reset_token, reset_token_expiry
                FROM Users
                WHERE email = @email
            `);

        if (result.recordset.length === 0) {
            return res.status(400).json(invalidResponse);
        }

        const user = result.recordset[0];
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
        const pool = await sql.connect(dbConfig);

        const result = await pool.request()
            .input("email", sql.VarChar, email)
            .query(`
                SELECT id, reset_token, reset_token_expiry
                FROM Users
                WHERE email = @email
            `);

        if (result.recordset.length === 0) {
            return res.status(400).json({ message: "Invalid or expired code." });
        }

        const user = result.recordset[0];
        const validCode = user.reset_token === hashOtp(code);
        const notExpired = user.reset_token_expiry && new Date(user.reset_token_expiry) > new Date();

        if (!validCode || !notExpired) {
            return res.status(400).json({ message: "Invalid or expired code. Please request a new one." });
        }

        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

        // Update password and invalidate the code (single-use)
        await pool.request()
            .input("id", sql.Int, user.id)
            .input("password", sql.VarChar, passwordHash)
            .query(`
                UPDATE Users
                SET password = @password, reset_token = NULL, reset_token_expiry = NULL
                WHERE id = @id
            `);

        res.json({ message: "Password updated successfully. You can now log in." });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});


// ======================================
// SUBMIT REPORT API
// ======================================
app.post("/submit-report", async (req, res) => {
    const { user_id, description, image, location } = req.body;

    if (!user_id || !description) {
        return res.status(400).json({ message: "User ID and description are required" });
    }

    try {
        const pool = await sql.connect(dbConfig);

        await pool.request()
            .input("user_id",     sql.Int,              user_id)
            .input("description", sql.VarChar(1000),     description)
            .input("image",       sql.NVarChar(sql.MAX), image || null)
            .input("location",    sql.VarChar(100),      location || null)
            .query(`
                INSERT INTO Reports (user_id, description, image, location)
                VALUES (@user_id, @description, @image, @location)
            `);

        res.json({ message: "Report submitted successfully" });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: err.message });
    }
});

// ======================================
// GET USER REPORTS API
// ======================================
app.get("/my-reports/:user_id", async (req, res) => {
    const { user_id } = req.params;

    try {
        const pool = await sql.connect(dbConfig);

        const result = await pool.request()
            .input("user_id", sql.Int, user_id)
            .query(`
                SELECT id, description, location, status, date
                FROM Reports
                WHERE user_id = @user_id
                ORDER BY date DESC
            `);

        res.json(result.recordset);

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

// ======================================
// DELETE ALL USER REPORTS API
// ======================================
app.delete("/clear-reports/:user_id", async (req, res) => {
    const { user_id } = req.params;

    try {
        const pool = await sql.connect(dbConfig);

        await pool.request()
            .input("user_id", sql.Int, user_id)
            .query("DELETE FROM Reports WHERE user_id = @user_id");

        res.json({ message: "Reports cleared successfully" });

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
