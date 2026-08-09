/**
 * One-off script to create a municipal worker / supervisor account.
 * Use this for quickly seeding test accounts. For real staff onboarding
 * once the system is live, use the /admin/create-staff endpoint instead
 * (see server.js) so it goes through Supervisor accounts, not the DB directly.
 *
 * Usage:
 *   node create-worker.js "Jane" "Doe" "jane@municipality.gov.za" "0821234567" "TempPass123!" municipal_worker
 *
 * Role must be one of: municipal_worker, supervisor, admin
 */

require("dotenv").config();
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const { validatePasswordStrength } = require("./passwordPolicy");

const [first_name, last_name, email, phone, password, role] = process.argv.slice(2);

if (!first_name || !last_name || !email || !phone || !password || !role) {
    console.log("Usage: node create-worker.js <first_name> <last_name> <email> <phone> <password> <role>");
    console.log("Role must be one of: municipal_worker, supervisor, admin");
    process.exit(1);
}

if (!["municipal_worker", "supervisor", "admin"].includes(role)) {
    console.log("❌ Invalid role. Must be: municipal_worker, supervisor, or admin");
    process.exit(1);
}

const pool = new Pool({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT) || 5432,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
});

async function main() {
    const strength = validatePasswordStrength(password);
    if (!strength.valid) {
        console.log("❌ That password doesn't meet the site's requirements:", strength.message);
        process.exit(1);
    }

    try {
        const existing = await pool.query("SELECT id FROM Users WHERE email = $1", [email]);
        if (existing.rows.length > 0) {
            console.log("❌ That email is already registered.");
            process.exit(1);
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const result = await pool.query(
            `INSERT INTO Users (first_name, last_name, email, phone, password, role, must_change_password)
             VALUES ($1, $2, $3, $4, $5, $6, true)
             RETURNING id, email, role`,
            [first_name, last_name, email, phone, passwordHash, role]
        );

        console.log("✅ Account created:");
        console.log(result.rows[0]);
        console.log(`They can log in at municipal-login.html with: ${email} / ${password}`);
        console.log("They will be required to set their own password on first login.");

    } catch (err) {
        console.error("❌ Error:", err.message);
    } finally {
        await pool.end();
    }
}

main();