const API_BASE = 'http://localhost:3000';

// Reads the same session shape /login now returns: includes token + role.
function getWorkerSession() {
    const sessionData = localStorage.getItem('user_session') || sessionStorage.getItem('user_session');
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

        tbody.innerHTML = reports.map(r => `
            <tr onclick="viewReport(${r.id})">
                <td>${r.image ? `<img class="thumb" src="${r.image}">` : `<div class="thumb"></div>`}</td>
                <td>${escapeHtml(r.description)}</td>
                <td>${escapeHtml(r.first_name)} ${escapeHtml(r.last_name)}</td>
                <td>${escapeHtml(r.location || 'Not provided')}</td>
                <td>${new Date(r.date).toLocaleDateString('en-ZA')}</td>
                <td>
                    <select class="status-select" onclick="event.stopPropagation()" onchange="updateStatus(${r.id}, this.value)">
                        ${['Received', 'Under Review', 'Assigned', 'Resolved'].map(s =>
                            `<option value="${s}" ${s === r.status ? 'selected' : ''}>${s}</option>`
                        ).join('')}
                    </select>
                </td>
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
    localStorage.removeItem('user_session');
    sessionStorage.removeItem('user_session');
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

window.addEventListener('load', () => {
    if (!enforceWorkerAccess()) return;

    const worker = getWorkerSession();
    const badge = document.getElementById('workerName');
    if (badge) {
        badge.textContent = worker.first_name || worker.email || 'Worker';
    }
    loadReports();
});