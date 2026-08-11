const API_BASE = 'http://localhost:3000';

// Reads the same session shape /login now returns: includes token + role.
// Stored under its own key so a municipal login can never overwrite
// (or be read as) a community member's session, and vice versa.
function getWorkerSession() {
    const sessionData = localStorage.getItem('municipal_session') || sessionStorage.getItem('municipal_session');
    if (!sessionData) return null;
    try {
        return JSON.parse(sessionData);
    } catch (err) {
        console.error('Failed to parse worker session:', err);
        return null;
    }
}

function authHeaders() {
    const worker = getWorkerSession();
    const token = worker ? worker.token : null;
    return {
        'Content-Type': 'application/json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {})
    };
}

// Kicks unauthenticated or non-worker sessions back to login.
// This is a UX convenience, not the real security boundary — the
// server's requireRole check on /reports is what actually protects
// the data, this just avoids showing a confusing empty dashboard.
function enforceWorkerAccess() {
    const worker = getWorkerSession();
    if (!worker || !worker.token || !['municipal_worker', 'supervisor'].includes(worker.role)) {
        alert('You need to log in first.');
        window.location.href = 'municipal-login.html';
        return false;
    }
    if (worker.must_change_password) {
        window.location.href = 'municipal-set-password.html';
        return false;
    }
    return true;
}

function statusClass(status) {
    return 'status-' + status.replace(/\s+/g, '_');
}

function debounce(fn, delay) {
    let timer;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => fn(...args), delay);
    };
}

async function loadReports() {
    const status = document.getElementById('statusFilter').value;
    const search = document.getElementById('searchInput').value.trim();

    const params = new URLSearchParams();
    if (status) params.set('status', status);
    if (search) params.set('search', search);

    const tbody = document.getElementById('reportsBody');

    try {
        const res = await fetch(`${API_BASE}/reports?${params.toString()}`, {
            headers: authHeaders()
        });

        if (res.status === 401 || res.status === 403) {
            window.location.href = 'municipal-login.html';
            return;
        }

        const reports = await res.json();

        if (!Array.isArray(reports) || reports.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="empty-state">No reports match these filters.</td></tr>`;
            return;
        }

        // The dashboard shows reports for quick viewing only — rows
        // aren't clickable there. Only municipal-reports.html sets
        // ROWS_CLICKABLE = true, which is where the actual
        // enlarge-into-detail interaction lives.
        const clickable = typeof ROWS_CLICKABLE !== 'undefined' && ROWS_CLICKABLE;

        tbody.innerHTML = reports.map(r => `
            <tr ${clickable ? `onclick="viewReport(${r.id})"` : ''} class="${clickable ? '' : 'view-only'}">
                <td>${r.image ? `<img class="thumb" src="${r.image}">` : `<div class="thumb"></div>`}</td>
                <td>${escapeHtml(r.description)}</td>
                <td>${escapeHtml(r.first_name)} ${escapeHtml(r.last_name)}</td>
                <td>${escapeHtml(r.location || 'Not provided')}</td>
                <td>${new Date(r.date).toLocaleDateString('en-ZA')}</td>
                <td><span class="status-pill status-${r.status.replace(/\s+/g, '_')}">${escapeHtml(r.status)}</span></td>
            </tr>
        `).join('');

    } catch (err) {
        console.error(err);
        tbody.innerHTML = `<tr><td colspan="6" class="empty-state">Could not reach the server. Is it running?</td></tr>`;
    }
}

const debouncedLoad = debounce(loadReports, 350);

async function updateStatus(reportId, newStatus) {
    try {
        const res = await fetch(`${API_BASE}/reports/${reportId}`, {
            method: 'PATCH',
            headers: authHeaders(),
            body: JSON.stringify({ status: newStatus })
        });
        const data = await res.json();

        if (!res.ok) {
            alert('Failed to update status: ' + data.message);
            loadReports(); // revert dropdown to real value
        }
    } catch (err) {
        console.error(err);
        alert('Could not connect to server.');
        loadReports();
    }
}

function logoutWorker() {
    localStorage.removeItem('municipal_session');
    sessionStorage.removeItem('municipal_session');
    window.location.href = 'municipal-login.html';
}

function viewReport(id) {
    window.location.href = `municipal-report.html?id=${id}`;
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str ?? '';
    return div.innerHTML;
}

async function loadUnreadBadge() {
    const badge = document.getElementById('bellBadge');
    if (!badge) return;

    try {
        const res = await fetch(`${API_BASE}/feedback/unread-count`, {
            headers: authHeaders()
        });
        if (!res.ok) return;
        const data = await res.json();

        if (data.count > 0) {
            badge.textContent = data.count > 9 ? '9+' : data.count;
            badge.classList.add('show');
        } else {
            badge.classList.remove('show');
        }
    } catch (err) {
        console.error('Could not load unread feedback count:', err);
    }
}

window.addEventListener('load', () => {
    if (!enforceWorkerAccess()) return;

    const worker = getWorkerSession();
    const badge = document.getElementById('workerName');
    if (badge) {
        badge.textContent = worker.first_name || worker.email || 'Worker';
    }

    // Only the dashboard has this table — municipal-report.html and
    // municipal-feedback.html run their own load logic instead.
    if (document.getElementById('reportsBody')) {
        loadReports();
    }

    loadUnreadBadge();
});
