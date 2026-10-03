// ============================================
// LIGHT / DARK MODE
// Load this in <head> on every page (with theme.css). It applies the
// saved theme immediately — before the page is drawn — so there's no
// flash of the wrong colours, then adds a toggle once the page loads:
//   - resident pages:  an item in the side menu
//   - municipal pages: a button above "Log out"
//   - other pages (login etc.): a small round button, bottom-right
//
// The choice is a per-device preference, so it lives in localStorage.
// Until someone picks, the device's own light/dark setting is followed.
// ============================================

(function () {
    const STORAGE_KEY = 'ciris_theme';
    const systemDark = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

    function savedTheme() {
        try {
            const value = localStorage.getItem(STORAGE_KEY);
            return value === 'dark' || value === 'light' ? value : null;
        } catch (err) {
            return null; // storage blocked (private mode etc.) — fall back to system
        }
    }

    function currentTheme() {
        return savedTheme() || (systemDark && systemDark.matches ? 'dark' : 'light');
    }

    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        updateToggleLabels(theme);
    }

    function updateToggleLabels(theme) {
        const nextIsDark = theme !== 'dark';
        document.querySelectorAll('[data-theme-toggle]').forEach(el => {
            const icon = nextIsDark ? '🌙' : '☀️';
            const text = nextIsDark ? 'Dark mode' : 'Light mode';
            el.setAttribute('aria-label', `Switch to ${text.toLowerCase()}`);
            el.title = `Switch to ${text.toLowerCase()}`;
            el.textContent = el.dataset.themeToggle === 'icon' ? icon : `${icon} ${text}`;
        });
    }

    function toggleTheme() {
        const next = currentTheme() === 'dark' ? 'light' : 'dark';
        try { localStorage.setItem(STORAGE_KEY, next); } catch (err) { /* still applies for this page */ }
        applyTheme(next);
    }

    function addToggle() {
        let toggle;
        const residentMenu = document.querySelector('#sidebar .sidebar-nav') || document.getElementById('sidebar');
        const staffSidebar = document.querySelector('aside .sidebar-bottom');

        if (staffSidebar) {
            toggle = document.createElement('button');
            toggle.type = 'button';
            toggle.className = 'theme-toggle-staff';
            toggle.dataset.themeToggle = 'text';
            staffSidebar.insertBefore(toggle, staffSidebar.firstChild);
        } else if (residentMenu) {
            // Same look as the other side-menu items (<p> elements)
            toggle = document.createElement('p');
            toggle.setAttribute('role', 'button');
            toggle.tabIndex = 0;
            toggle.dataset.themeToggle = 'text';
            toggle.addEventListener('keydown', e => {
                if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleTheme(); }
            });
            residentMenu.appendChild(toggle);
        } else {
            toggle = document.createElement('button');
            toggle.type = 'button';
            toggle.className = 'theme-toggle-floating';
            toggle.dataset.themeToggle = 'icon';
            document.body.appendChild(toggle);
        }

        toggle.addEventListener('click', toggleTheme);
        updateToggleLabels(currentTheme());
    }

    // 1. Apply straight away (this script runs in <head>, before the body is drawn)
    applyTheme(currentTheme());

    // 2. Follow the device setting live, until the user makes their own choice
    if (systemDark && systemDark.addEventListener) {
        systemDark.addEventListener('change', () => {
            if (!savedTheme()) applyTheme(currentTheme());
        });
    }

    // 3. Keep other open tabs in sync when the choice changes
    window.addEventListener('storage', e => {
        if (e.key === STORAGE_KEY) applyTheme(currentTheme());
    });

    // 4. Add the toggle once the page exists
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', addToggle);
    } else {
        addToggle();
    }

    window.toggleTheme = toggleTheme;
})();
