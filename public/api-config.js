// ============================================
// API LOCATION (shared by every page — load this before other scripts)
//
// When the pages are served by server.js (`npm start`, or once deployed),
// the API is on the same origin, so requests use relative paths ("").
// When a page is opened some other way — VS Code Live Server, or by
// double-clicking the .html file — that server can't answer API calls,
// so fall back to the local Node server.
// ============================================
const API_SERVER_PORT = '3000';

const API_BASE = (location.protocol === 'file:' ||
                  (location.port !== '' && location.port !== API_SERVER_PORT))
    ? `http://localhost:${API_SERVER_PORT}`
    : '';

// Coming back with the browser's Back button can show a saved snapshot of
// the page as it was left (the "back/forward cache"), skipping the login
// check and showing stale data. When that happens, reload instead, so the
// page checks the session again and fetches fresh data.
window.addEventListener('pageshow', event => {
    if (event.persisted) location.reload();
});

// Reads a fetch Response as JSON without crashing on an empty or HTML
// body (e.g. when the request reached the wrong server).
async function readJsonSafely(res) {
    const type = res.headers.get('content-type') || '';
    if (!type.includes('application/json')) return null;
    try {
        return await res.json();
    } catch (err) {
        return null;
    }
}

// Uploaded photos are stored as "/uploads/..." paths on the API server.
// Prefix them so they still load when the page comes from somewhere else.
function assetUrl(path) {
    return (typeof path === 'string' && path.startsWith('/uploads/')) ? API_BASE + path : path;
}
