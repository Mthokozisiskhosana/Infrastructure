// ============================================
// SERVER-SIDE PASSWORD POLICY
// Never trust client-side validation alone — this is the real gate.
// ============================================

const MIN_LENGTH = 8;

/**
 * Returns { valid: boolean, message: string|null }
 */
function validatePasswordStrength(password) {
    if (typeof password !== "string") {
        return { valid: false, message: "Password is required" };
    }
    if (password.length < MIN_LENGTH) {
        return { valid: false, message: `Password must be at least ${MIN_LENGTH} characters long` };
    }
    if (!/[A-Z]/.test(password)) {
        return { valid: false, message: "Password must contain at least one uppercase letter" };
    }
    if (!/[a-z]/.test(password)) {
        return { valid: false, message: "Password must contain at least one lowercase letter" };
    }
    if (!/[0-9]/.test(password)) {
        return { valid: false, message: "Password must contain at least one number" };
    }
    if (!/[^A-Za-z0-9]/.test(password)) {
        return { valid: false, message: "Password must contain at least one special character (e.g. ! @ # $ %)" };
    }
    return { valid: true, message: null };
}

module.exports = { validatePasswordStrength, MIN_LENGTH };
