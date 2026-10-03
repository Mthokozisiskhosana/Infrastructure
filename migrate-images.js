/**
 * One-off migration: moves base64 images out of the database into
 * /uploads files (see imageStorage.js), replacing each value with its
 * short "/uploads/..." URL.
 *
 * Before changing anything it writes every old value to
 * backups/images-backup-<timestamp>.json, so the migration can be undone.
 * Safe to run more than once — rows already migrated are skipped.
 *
 * Usage:
 *   node migrate-images.js
 */

require("dotenv").config({ quiet: true });
const fs = require("fs/promises");
const path = require("path");
const { Pool } = require("pg");
const { parseImageDataUrl, saveImage, deleteImage } = require("./imageStorage");

const useSSL = process.env.DB_SSL !== "false";
const pool = process.env.DATABASE_URL
    ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: useSSL ? { rejectUnauthorized: false } : false })
    : new Pool({
        host: process.env.DB_HOST,
        port: Number(process.env.DB_PORT) || 5432,
        database: process.env.DB_NAME,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        ssl: useSSL ? { rejectUnauthorized: false } : false
    });

const TARGETS = [
    { table: "Reports", column: "image", folder: "reports" },
    { table: "Users", column: "profile_picture", folder: "profiles" }
];

async function main() {
    // 1. Back up every base64 value before touching anything
    const backup = {};
    for (const t of TARGETS) {
        const result = await pool.query(
            `SELECT id, ${t.column} AS value FROM ${t.table} WHERE ${t.column} LIKE 'data:%'`
        );
        backup[`${t.table}.${t.column}`] = result.rows;
    }

    const total = Object.values(backup).reduce((n, rows) => n + rows.length, 0);
    if (total === 0) {
        console.log("Nothing to migrate — no base64 images left in the database.");
        return;
    }

    const backupDir = path.join(__dirname, "backups");
    await fs.mkdir(backupDir, { recursive: true });
    const backupFile = path.join(backupDir, `images-backup-${new Date().toISOString().replace(/[:.]/g, "-")}.json`);
    await fs.writeFile(backupFile, JSON.stringify(backup));
    console.log(`Backed up ${total} image value(s) to ${path.relative(__dirname, backupFile)}`);

    // 2. Write each image to disk, then point the row at the file
    let migrated = 0;
    const skipped = [];

    for (const t of TARGETS) {
        for (const row of backup[`${t.table}.${t.column}`]) {
            const parsed = parseImageDataUrl(row.value);
            if (!parsed) {
                skipped.push(`${t.table} #${row.id} (unsupported or corrupt image data)`);
                continue;
            }

            const url = await saveImage(parsed, t.folder);
            try {
                await pool.query(
                    `UPDATE ${t.table} SET ${t.column} = $1 WHERE id = $2 AND ${t.column} = $3`,
                    [url, row.id, row.value]
                );
                migrated++;
                console.log(`  ${t.table} #${row.id} -> ${url} (${Math.round(parsed.buffer.length / 1024)} KB)`);
            } catch (err) {
                await deleteImage(url);
                skipped.push(`${t.table} #${row.id} (${err.message})`);
            }
        }
    }

    console.log(`\nMigrated ${migrated} of ${total} image(s).`);
    if (skipped.length > 0) {
        console.log("Left unchanged:");
        skipped.forEach(s => console.log("  - " + s));
    }
}

main()
    .catch(err => {
        console.error("Migration failed:", err.message);
        process.exitCode = 1;
    })
    .finally(() => pool.end());
