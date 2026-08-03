/* ============================================
   PASSWORD RULES (shared client-side logic)
   Used by: login.html (register tab) and reset-password.html
   ============================================ */

// Requirements: 8+ chars, 1 uppercase, 1 lowercase, 1 number, 1 special char
const PASSWORD_RULES = {
    minLength: 8,
    hasUpper: /[A-Z]/,
    hasLower: /[a-z]/,
    hasNumber: /[0-9]/,
    hasSpecial: /[^A-Za-z0-9]/
};

/**
 * Checks a password against all rules.
 * Returns { valid: bool, failedRules: [labels], score: 0-4 }
 */
function checkPasswordStrength(password) {
    const failedRules = [];
    let score = 0;

    if (password.length >= PASSWORD_RULES.minLength) score++;
    else failedRules.push('At least 8 characters');

    if (PASSWORD_RULES.hasUpper.test(password)) score++;
    else failedRules.push('One uppercase letter (A-Z)');

    if (PASSWORD_RULES.hasLower.test(password)) score++;
    else failedRules.push('One lowercase letter (a-z)');

    if (PASSWORD_RULES.hasNumber.test(password)) score++;
    else failedRules.push('One number (0-9)');

    if (PASSWORD_RULES.hasSpecial.test(password)) score++;
    else failedRules.push('One special character (!@#$%^&* etc.)');

    return {
        valid: failedRules.length === 0,
        failedRules,
        score // 0-5
    };
}

/**
 * Wires a password input to a strength bar + a live checklist.
 * @param {string} inputId - id of the password <input>
 * @param {string} barId - id of the strength-bar <div>
 * @param {string} listId - id of a <ul> (or any container) to show missing rules
 * @param {string} submitBtnId - id of the submit button to enable/disable
 */
function bindPasswordStrengthUI(inputId, barId, listId, submitBtnId) {
    const input = document.getElementById(inputId);
    const bar = document.getElementById(barId);
    const list = document.getElementById(listId);
    const btn = submitBtnId ? document.getElementById(submitBtnId) : null;

    if (!input) return;

    input.addEventListener('input', () => {
        const result = checkPasswordStrength(input.value);

        if (bar) {
            bar.className = 'strength-bar';
            if (input.value.length === 0) {
                bar.style.width = '0';
            } else if (result.score <= 2) {
                bar.classList.add('weak');
            } else if (result.score <= 4) {
                bar.classList.add('medium');
            } else {
                bar.classList.add('strong');
            }
        }

        if (list) {
            if (result.valid || input.value.length === 0) {
                list.innerHTML = '';
                list.style.display = 'none';
            } else {
                list.style.display = 'block';
                list.innerHTML = '<strong>Password needs:</strong><ul style="margin:4px 0 0 18px;padding:0;">' +
                    result.failedRules.map(r => `<li>${r}</li>`).join('') +
                    '</ul>';
            }
        }

        if (btn) {
            btn.disabled = !result.valid;
        }
    });
}

// Export for Node (server-side reuse) and browser
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { checkPasswordStrength, PASSWORD_RULES };
}
