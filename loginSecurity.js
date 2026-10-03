// ============================================
// LOGIN SECURITY — brute-force protection
//
// Counts failed attempts per "key" in the LoginAttempts table, e.g.
//   login:<email>        wrong passwords for an account
//   ip:<address>         wrong passwords from one network address
//   reset:<email>        wrong password-reset codes
//   emailchange:<userId> wrong email-change codes
//
// Stored in the database (not memory) so counters survive restarts —
// Render's free servers restart every time they wake from sleep.
// ============================================

const LOGIN_MAX_FAILURES = 5;                    // wrong passwords before a lock
const LOGIN_LOCK_STEPS_SECONDS = [30, 60, 300, 900]; // 30s, 1 min, 5 min, 15 min for repeat lockouts
const IP_MAX_FAILURES = 20;                      // wrong passwords from one address...
const IP_LOCK_SECONDS = 15 * 60;                 // ...locks that address for 15 minutes
const CODE_MAX_FAILURES = 5;                     // wrong 6-digit codes before the code is cancelled
const FAILURE_WINDOW_MINUTES = 15;               // older failures stop counting
const LOCKOUT_MEMORY_HOURS = 1;                  // after this long, lock durations start from 30s again

function createLoginSecurity(pool) {
    async function ensureTable() {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS LoginAttempts (
                attempt_key     VARCHAR(255) PRIMARY KEY,
                failed_count    INTEGER   NOT NULL DEFAULT 0,
                lockouts        INTEGER   NOT NULL DEFAULT 0,
                locked_until    TIMESTAMP,
                last_failed_at  TIMESTAMP
            )
        `);
    }

    /** Seconds until the longest active lock among these keys ends (0 = not locked). */
    async function getLockSeconds(keys) {
        const result = await pool.query(
            `SELECT COALESCE(MAX(CEIL(EXTRACT(EPOCH FROM (locked_until - NOW())))), 0)::int AS secs
             FROM LoginAttempts
             WHERE attempt_key = ANY($1) AND locked_until > NOW()`,
            [keys]
        );
        return result.rows[0].secs;
    }

    /**
     * Records one failure for a key.
     * @param {object} opts
     *   limit       failures allowed before the limit is reached
     *   lockFor(n)  seconds to lock for on the n-th lockout, or omit to not lock
     *               (the caller handles reaching the limit, e.g. cancels a code)
     * @returns {Promise<{ attemptsLeft: number, limitReached: boolean, lockedFor: number, lockouts: number }>}
     */
    async function recordFailure(key, { limit, lockFor } = {}) {
        const result = await pool.query(
            `INSERT INTO LoginAttempts (attempt_key, failed_count, last_failed_at)
             VALUES ($1, 1, NOW())
             ON CONFLICT (attempt_key) DO UPDATE SET
                 failed_count = CASE
                     WHEN LoginAttempts.last_failed_at < NOW() - make_interval(mins => $2)
                         THEN 1
                     ELSE LoginAttempts.failed_count + 1
                 END,
                 lockouts = CASE
                     WHEN LoginAttempts.locked_until < NOW() - make_interval(hours => $3)
                         THEN 0
                     ELSE LoginAttempts.lockouts
                 END,
                 last_failed_at = NOW()
             RETURNING failed_count, lockouts`,
            [key, FAILURE_WINDOW_MINUTES, LOCKOUT_MEMORY_HOURS]
        );

        const { failed_count: failedCount, lockouts } = result.rows[0];
        if (failedCount < limit) {
            return { attemptsLeft: limit - failedCount, limitReached: false, lockedFor: 0, lockouts };
        }

        if (!lockFor) {
            await clear(key);
            return { attemptsLeft: 0, limitReached: true, lockedFor: 0, lockouts };
        }

        const newLockouts = lockouts + 1;
        const seconds = lockFor(newLockouts);
        await pool.query(
            `UPDATE LoginAttempts
             SET failed_count = 0, lockouts = $2, locked_until = NOW() + make_interval(secs => $3)
             WHERE attempt_key = $1`,
            [key, newLockouts, seconds]
        );
        return { attemptsLeft: 0, limitReached: true, lockedFor: seconds, lockouts: newLockouts };
    }

    async function clear(key) {
        await pool.query("DELETE FROM LoginAttempts WHERE attempt_key = $1", [key]);
    }

    /** Hourly tidy-up of rows that no longer affect anything. */
    function startCleanup() {
        const run = () => pool.query(
            `DELETE FROM LoginAttempts
             WHERE last_failed_at < NOW() - INTERVAL '1 day'
               AND (locked_until IS NULL OR locked_until < NOW())`
        ).catch(err => console.log("[login-security] cleanup failed:", err.message));
        setInterval(run, 60 * 60 * 1000);
    }

    return { ensureTable, getLockSeconds, recordFailure, clear, startCleanup };
}

/** Lock duration for an account's n-th lockout in a row: 30s, 1 min, 5 min, then 15 min. */
function loginLockSeconds(lockoutNumber) {
    return LOGIN_LOCK_STEPS_SECONDS[Math.min(lockoutNumber, LOGIN_LOCK_STEPS_SECONDS.length) - 1];
}

/** "30 seconds", "1 minute", "5 minutes" */
function formatDuration(seconds) {
    if (seconds < 60) return `${seconds} second${seconds === 1 ? "" : "s"}`;
    const minutes = Math.ceil(seconds / 60);
    return `${minutes} minute${minutes === 1 ? "" : "s"}`;
}

module.exports = {
    createLoginSecurity,
    loginLockSeconds,
    formatDuration,
    LOGIN_MAX_FAILURES,
    IP_MAX_FAILURES,
    IP_LOCK_SECONDS,
    CODE_MAX_FAILURES
};
