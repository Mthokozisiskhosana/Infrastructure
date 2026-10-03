// ============================================
// LOGIN LOCK COUNTDOWN (shared by login.html and municipal-login.html)
//
// The server is what actually enforces the lock (5 wrong passwords, then
// 30s — longer for repeat lockouts). This only shows the countdown and
// keeps the Sign In button disabled until it ends, including after a
// page refresh.
// ============================================

function formatCountdown(seconds) {
    if (seconds < 60) return `${seconds}s`;
    const m = Math.floor(seconds / 60);
    const s = String(seconds % 60).padStart(2, '0');
    return `${m}:${s}`;
}

/**
 * @param {object} opts
 *   storageKey    where the lock end time is remembered (survives refresh)
 *   button        the Sign In button
 *   idleLabel     button text when not locked
 *   showMessage   (text) => void — display the lock message
 *   clearMessage  () => void — hide it when the lock ends
 */
function createLoginLock({ storageKey, button, idleLabel, showMessage, clearMessage }) {
    let timer = null;

    function tick(until) {
        const left = Math.ceil((until - Date.now()) / 1000);
        if (left <= 0) {
            stop();
            return;
        }
        button.disabled = true;
        button.textContent = `Try again in ${formatCountdown(left)}`;
        showMessage(`Too many failed login attempts. For your security, sign-in is paused — please wait ${formatCountdown(left)}.`);
    }

    function run(until) {
        clearInterval(timer);
        tick(until);
        timer = setInterval(() => tick(until), 250);
    }

    function start(seconds) {
        const until = Date.now() + seconds * 1000;
        try { sessionStorage.setItem(storageKey, String(until)); } catch (err) { /* countdown still runs */ }
        run(until);
    }

    function stop() {
        clearInterval(timer);
        timer = null;
        try { sessionStorage.removeItem(storageKey); } catch (err) { /* ignore */ }
        button.disabled = false;
        button.textContent = idleLabel;
        clearMessage();
    }

    // Pick up a countdown that was running before the page was refreshed
    function resume() {
        let until = 0;
        try { until = Number(sessionStorage.getItem(storageKey)) || 0; } catch (err) { /* ignore */ }
        if (until > Date.now()) run(until);
    }

    return { start, resume, isLocked: () => timer !== null };
}
