const express = require("express");
const sql = require("mssql");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

app.get("/", (req, res) => {
    res.json({ message: "Server is running!" });
});


// ======================================
// SQL SERVER CONFIG 
// ======================================
const dbConfig = {
    server: "MTHOKOZISI\\SQLEXPRESS04",
    database: "CommunityDB",
    port: 1433,
    user: "communityuser",
    password: "Admin@1234",
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

    // Validate email domain
    const allowedDomains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com'];
    const emailDomain = email.split('@')[1];

    if (!emailDomain || !allowedDomains.includes(emailDomain.toLowerCase())) {
        return res.status(400).json({ message: "Please use a personal email from an allowed domain (gmail.com, yahoo.com, outlook.com, hotmail.com, icloud.com)" });
    }

    // Validate South African phone number
    const phoneRegex = /^(\+27|0)[6-8][0-9]{8}$/;
    if (!phoneRegex.test(phone)) {
        return res.status(400).json({ message: "Please enter a valid South African phone number (e.g., 0712345678 or +27712345678)" });
    }

    try {
        const pool = await sql.connect(dbConfig);

        // Check if user exists
        const checkUser = await pool.request()
            .input("email", sql.VarChar, email)
            .query("SELECT * FROM Users WHERE email = @email");

        if (checkUser.recordset.length > 0) {
            return res.status(400).json({ message: "Email already exists" });
        }

        // Insert user
        await pool.request()
            .input("first_name", sql.VarChar, first_name)
            .input("last_name", sql.VarChar, last_name)
            .input("email", sql.VarChar, email)
            .input("phone", sql.VarChar, phone)
            .input("password", sql.VarChar, password)
            .query(`
                INSERT INTO Users (first_name, last_name, email, phone, password)
                VALUES (@first_name, @last_name, @email, @phone, @password)
            `);

        res.json({ message: "User registered successfully" });

    }catch (err) {
    console.log("FULL ERROR:", err);
    res.status(500).json({ message: err.message });
}
});


// ======================================
// LOGIN API
// ======================================
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    // Validate email domain
    const allowedDomains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com'];
    const emailDomain = email.split('@')[1];

    if (!emailDomain || !allowedDomains.includes(emailDomain.toLowerCase())) {
        return res.status(400).json({ message: "Please use a personal email from an allowed domain (gmail.com, yahoo.com, outlook.com, hotmail.com, icloud.com)" });
    }

    try {
        const pool = await sql.connect(dbConfig);

        const result = await pool.request()
            .input("email", sql.VarChar, email)
            .input("password", sql.VarChar, password)
            .query(`
                SELECT id, first_name, last_name, email, phone 
                FROM Users 
                WHERE email = @email AND password = @password
            `);

        if (result.recordset.length === 0) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        const user = result.recordset[0];

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
// RESET PASSWORD API
// ======================================
app.post("/reset-password", async (req, res) => {
    const { email, password } = req.body;

    try {
        const pool = await sql.connect(dbConfig);

        // Check if user exists
        const checkUser = await pool.request()
            .input("email", sql.VarChar, email)
            .query("SELECT * FROM Users WHERE email = @email");

        if (checkUser.recordset.length === 0) {
            return res.status(404).json({ message: "Email not found" });
        }

        // Update password
        await pool.request()
            .input("email", sql.VarChar, email)
            .input("password", sql.VarChar, password)
            .query(`
                UPDATE Users
                SET password = @password
                WHERE email = @email
            `);

        res.json({ message: "Password reset successfully" });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});
// ======================================
// CHECK EMAIL EXISTS (Step 1)
// ======================================
app.post("/check-email", async (req, res) => {
    const { email } = req.body;
    try {
        const pool  = await sql.connect(dbConfig);
        const check = await pool.request()
            .input("email", sql.VarChar, email)
            .query("SELECT id FROM Users WHERE email = @email");

        if (check.recordset.length === 0)
            return res.status(404).json({ message: "No account found with that email" });

        res.json({ message: "Email found" });
    } catch (err) {
        res.status(500).json({ message: "Server error" });
    }
});

// ======================================
// RESET PASSWORD (Step 2)
// ======================================
app.post("/forgot-password", async (req, res) => {
    const { email, newPassword } = req.body;
    try {
        const pool = await sql.connect(dbConfig);
        await pool.request()
            .input("email",       sql.VarChar, email)
            .input("newPassword", sql.VarChar, newPassword)
            .query("UPDATE Users SET password = @newPassword WHERE email = @email");

        res.json({ message: "Password updated successfully" });
    } catch (err) {
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