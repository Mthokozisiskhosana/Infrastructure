function openSidebar() {
  document.getElementById("sidebar").classList.add("active");
  document.getElementById("overlay").classList.add("active");
}

function closeSidebar() {
  document.getElementById("sidebar").classList.remove("active");
  document.getElementById("overlay").classList.remove("active");
}

function goToProfile() {
  window.location.href = 'profile.html';
}

function logout() {
  // Clear session data
  localStorage.removeItem('user_session');
  sessionStorage.removeItem('user_session');

  // replace() so the Back button can't return to the logged-in page
  window.location.replace('login.html');
}

// Call this instead of a raw redirect whenever a fetch comes back 401/403.
// Clearing the session here (not just redirecting) is what prevents an
// infinite bounce between login.html and whichever page made the request —
// without this, a stale/expired token never gets removed, and login.html
// keeps sending the user right back to a page that will reject it again.
function handleUnauthorized() {
  localStorage.removeItem('user_session');
  sessionStorage.removeItem('user_session');
  window.location.replace('login.html');
}

// Reads the "exp" (expiry, in seconds) from a JWT without verifying it —
// the server still verifies every request; this just lets the page notice
// an expired login instead of carrying on as that user.
function getTokenExpiry(token) {
    try {
        const payload = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
        const data = JSON.parse(atob(payload));
        return typeof data.exp === 'number' ? data.exp * 1000 : null;
    } catch (err) {
        return null;
    }
}

function clearUserSession() {
    localStorage.removeItem('user_session');
    sessionStorage.removeItem('user_session');
}

// Returns the logged-in community member, or null if there is no valid,
// unexpired community-member session (invalid ones are cleared).
function getCurrentUser() {
    const sessionData = sessionStorage.getItem('user_session');
    if (!sessionData) return null;

    try {
        const user = JSON.parse(sessionData);
        // Defense in depth: this key is for community members only.
        // A municipal_worker/supervisor session should never grant
        // access here, even if something upstream stored one under
        // this key by mistake.
        if (!user || !user.id || !user.token || user.role !== 'community_member') {
            clearUserSession();
            return null;
        }

        const expiresAt = getTokenExpiry(user.token);
        if (!expiresAt || expiresAt <= Date.now()) {
            clearUserSession();
            return null;
        }

        return user;
    } catch (err) {
        console.error('Failed to parse user session:', err);
        clearUserSession();
        return null;
    }
}

// Page guard for every resident page (they all load script.js).
// Mirrors the municipal portal's enforceWorkerAccess(): no valid login
// means a "log in first" message and a trip to the login page, before
// any of the page's own code tries to use the missing user.
(function requireCommunityLogin() {
    // Logins now live in sessionStorage (cleared when the browser closes).
    // Remove any leftover login saved by the older localStorage version.
    localStorage.removeItem('user_session');

    // Was this a real resident login that has simply timed out?
    let expired = false;
    try {
        const saved = JSON.parse(sessionStorage.getItem('user_session'));
        expired = !!(saved && saved.token && saved.role === 'community_member');
    } catch (err) { /* junk session — treat as not logged in */ }

    if (getCurrentUser()) return;

    alert(expired
        ? 'Your session has expired. Please log in again.'
        : 'You need to log in first.');
    window.location.replace('login.html');
})();

// Returns the JWT saved at login, or null if not signed in.
function getAuthToken() {
    const user = getCurrentUser();
    return user ? user.token : null;
}

// Standard headers for authenticated JSON requests.
function authHeaders() {
    const token = getAuthToken();
    return {
        'Content-Type': 'application/json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {})
    };
}

// Swaps the sidebar avatar's emoji for the user's real profile
// picture, if they have one set. Falls back to the emoji otherwise.
function updateSidebarAvatar(user) {
    const el = document.getElementById('sidebarAvatar');
    if (!el) return;

    if (user && user.profile_picture) {
        el.innerHTML = `<img src="${assetUrl(user.profile_picture)}" alt="Profile">`;
    } else {
        el.innerHTML = '👤';
    }
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str ?? '';
    return div.innerHTML;
}

function getReportsKey() {
    const user = getCurrentUser();
    if (!user) return 'reports';
    const id = user.id || user.email || 'anonymous';
    return `reports_${String(id).replace(/[^a-zA-Z0-9_-]/g, '_')}`;
}

/* Report Submission */

let imageData = "";
let gpsData = "";
let locationSource = "";      // "photo" | "device" | ""
let locationPending = false;  // true while the one-off device reading is in progress
let photoToken = 0;           // bumps per photo, so a slow result from an older photo is ignored

/* IMAGE SOURCE CHOICE */
function chooseImageSource() {
    const takePhoto = confirm("How would you like to add an image?\n\nOK = Take Photo with Camera\nCancel = Choose from Gallery");
    pickImage(takePhoto);
}

// Opens the phone's own camera app (capture) or the gallery. Both hand
// back the original photo file — including its EXIF metadata, which is
// where the camera stores the GPS location.
function pickImage(useCamera) {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = "image/*";
    if (useCamera) input.capture = "environment";

    input.onchange = e => {
        const file = e.target.files[0];
        if (file) handleSelectedImage(file);
    };

    input.click();
}

async function handleSelectedImage(file) {
    const token = ++photoToken;
    const previewBox = document.getElementById("previewBox");

    imageData = "";
    gpsData = "";
    locationSource = "";
    locationPending = false;
    previewBox.innerText = "Processing photo...";
    setLocationStatus("Reading location from photo...");

    // 1. Location from the photo's metadata (read from the ORIGINAL file —
    //    shrinking it below re-encodes the image and drops the metadata).
    let photoCoords = null;
    try {
        photoCoords = readExifGps(await file.arrayBuffer());
    } catch (err) {
        console.warn("Could not read photo metadata:", err);
    }

    // 2. Shrunk copy for preview + upload
    try {
        const dataUrl = await compressImage(file);
        if (token !== photoToken) return; // a newer photo was picked meanwhile
        imageData = dataUrl;
        previewBox.innerHTML = `<img src="${imageData}">`;
    } catch (err) {
        if (token !== photoToken) return;
        previewBox.innerText = "Could not read that image. Please choose a JPEG or PNG photo.";
        setLocationStatus("Location not captured");
        return;
    }

    // 3. Photo location if it has one, otherwise ONE device reading
    if (photoCoords) {
        setReportLocation(photoCoords, "photo");
    } else {
        captureDeviceLocationOnce(token);
    }
}

// Fallback for photos without GPS metadata: a single high-accuracy reading,
// locked in for this report (no re-capture button, so it can't keep moving).
function captureDeviceLocationOnce(token) {
    if (!navigator.geolocation) {
        setLocationStatus("⚠️ This photo has no location data and this device can't share its location. You can still submit, but the report won't have a location.");
        return;
    }

    locationPending = true;
    setLocationStatus("This photo has no location data — getting your device's location...");

    navigator.geolocation.getCurrentPosition(pos => {
        if (token !== photoToken) return;
        locationPending = false;
        setReportLocation({
            lat: pos.coords.latitude,
            lng: pos.coords.longitude,
            accuracy: pos.coords.accuracy
        }, "device");
    }, err => {
        if (token !== photoToken) return;
        locationPending = false;
        const reason = err.code === 1 ? "location access was denied" : "your location couldn't be found";
        setLocationStatus(`⚠️ This photo has no location data and ${reason}. You can still submit, but the report won't have a location.`);
    }, { enableHighAccuracy: true, timeout: 15000, maximumAge: 0 });
}

function setReportLocation(coords, source) {
    gpsData = `${coords.lat.toFixed(6)}, ${coords.lng.toFixed(6)}`;
    locationSource = source;

    if (source === "photo") {
        setLocationStatus(`📸 Location from photo: ${gpsData}`);
    } else {
        const accuracy = coords.accuracy ? ` (accurate to about ${Math.round(coords.accuracy)} m)` : "";
        setLocationStatus(`📱 Photo had no location, so your device's location was used: ${gpsData}${accuracy}`);
    }
}

function setLocationStatus(text) {
    const gpsBox = document.getElementById("gpsBox");
    if (gpsBox) gpsBox.innerText = text;
}

/* CLEAR FORM - FIXED (Added this function) */
function clearForm(){
    // Clear textarea
    const descInput = document.getElementById("description");
    if(descInput) descInput.value = "";
    
    // Clear image (bumping the token discards any location still loading)
    photoToken++;
    imageData = "";
    const previewBox = document.getElementById("previewBox");
    if(previewBox) previewBox.innerText = "No image captured";

    // Clear location
    gpsData = "";
    locationSource = "";
    locationPending = false;
    setLocationStatus("📍 Location will be taken from your photo");
    
    console.log("Form cleared successfully");
}

function submitReport(){
    const desc = document.getElementById("description").value;

    if(!desc){
        alert("Please describe the issue");
        return;
    }

    if(locationPending){
        alert("Still getting your location — please wait a moment and try again.");
        return;
    }

    // Get logged-in user
    const user = getCurrentUser();
    if(!user){
        window.location.href = 'login.html';
        return;
    }

    let report = {
        user_id:     user.id,
        description: desc,
        image:       imageData,
        location:    gpsData
    };

    // Send to server 
    fetch(`${API_BASE}/submit-report`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify(report)
    })
    .then(res => res.json().then(data => ({ status: res.status, data })))
    .then(({ status, data }) => {
        if (status === 409) {
            alert(data.message || "This report has been submitted before.");
            return;
        }
        if(data.message === "Report submitted successfully"){
            clearForm();

            const msg = document.getElementById("successMessage");
            if(msg){
                msg.style.display = "block";
                setTimeout(() => { msg.style.display = "none"; }, 3000);
            }

            loadReports(); // refresh the list
        } else {
            alert("Failed to submit: " + data.message);
        }
    })
    .catch(err => {
        console.error(err);
        alert("Could not connect to server.");
    });
}

/* REPORT PHOTOS */

// Only render photos the server itself stored (report photos and
// after-repair photos), never arbitrary strings.
const UPLOADED_PHOTO_REGEX = /^\/uploads\/(reports|repairs)\/[0-9a-f-]{36}\.(jpg|png|webp|gif)$/;

function isUploadedPhoto(path) {
    return typeof path === "string" && UPLOADED_PHOTO_REGEX.test(path);
}

// A labelled thumbnail that opens the full-size photo in a new tab.
function photoTile(path, label, isAfter) {
    const url = assetUrl(path);
    return `
        <a class="photo-tile${isAfter ? ' photo-tile--after' : ''}" href="${url}" target="_blank" rel="noopener">
            <img src="${url}" alt="${escapeHtml(label)}">
            <span>${isAfter ? '📸 ' : ''}${escapeHtml(label)}</span>
        </a>
    `;
}

function formatShortDate(dateStr) {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return "a recent date";
    return d.toLocaleDateString('en-ZA', { day: 'numeric', month: 'short', year: 'numeric' });
}

/* SHOW REPORTS */
function loadReports(){
    const user = getCurrentUser();
    if(!user){
        window.location.href = 'login.html';
        return;
    }

    fetch(`${API_BASE}/my-reports/${user.id}`, {
        headers: authHeaders()
    })
    .then(res => {
        if(res.status === 401 || res.status === 403){
            handleUnauthorized();
            return null;
        }
        return res.json();
    })
    .then(reports => {
        const list = document.getElementById("reportList");
        if(!list || !Array.isArray(reports)) return;

        list.innerHTML = "";

        if(reports.length === 0){
            list.innerHTML = `<div class="report-box">No reports submitted yet</div>`;
            return;
        }

        reports.forEach(report => {
            // Residents may only withdraw a report the municipality
            // hasn't started on yet — the server enforces the same rule.
            const canDelete = report.status === "Received";
            const resolved = report.status === "Resolved";
            const hasBefore = isUploadedPhoto(report.image);
            const hasAfter = isUploadedPhoto(report.after_image);

            let div = document.createElement("div");
            div.className = "report-box";
            div.innerHTML = `
                <p><strong>Issue:</strong> ${escapeHtml(report.description)}</p>
                <p><strong>Date:</strong> ${new Date(report.date).toLocaleString('en-ZA', {timeZone: 'Africa/Johannesburg'})}</p>
                <p><strong>Location:</strong> ${escapeHtml(report.location || "Not provided")}</p>
                <p><strong>Status:</strong> ${escapeHtml(report.status)} ${resolved ? '✅' : '⏳'}</p>
                ${hasBefore || hasAfter ? `
                    <div class="report-photos">
                        ${hasBefore ? photoTile(report.image, "Your photo") : ''}
                        ${hasAfter ? photoTile(report.after_image, "After repair", true) : ''}
                    </div>
                ` : ''}
                ${hasAfter ? `
                    <p class="repair-done-note">✅ Fixed — the municipality uploaded a photo of the completed repair on ${formatShortDate(report.after_image_at)}.</p>
                ` : ''}
                ${canDelete
                    ? `<button class="delete-report-btn" onclick="deleteReport(${Number(report.id)})">🗑️ Delete this report</button>`
                    : resolved
                        ? ''
                        : `<p class="delete-locked-note">🔒 The municipality is working on this report, so it can't be deleted.</p>`
                }
            `;
            list.appendChild(div);
        });
    })
    .catch(err => {
        console.error(err);
    });
}

/* DELETE ONE REPORT */
function deleteReport(reportId){
    const user = getCurrentUser();
    if(!user){
        window.location.href = 'login.html';
        return;
    }

    if(!confirm("Delete this report? This cannot be undone.")) return;

    fetch(`${API_BASE}/reports/${reportId}`, {
        method: 'DELETE',
        headers: authHeaders()
    })
    .then(res => res.json().then(data => ({ status: res.status, data })))
    .then(({ status, data }) => {
        if(status === 401){
            handleUnauthorized();
            return;
        }
        if(status === 200){
            loadReports(); // refresh the list
            return;
        }
        alert(data.message || "Could not delete the report.");
        loadReports(); // status may have changed since the page loaded
    })
    .catch(err => {
        console.error(err);
        alert("Could not connect to server.");
    });
}

function loadProfile(){
    const sessionData = sessionStorage.getItem('user_session');
    if(!sessionData){
        window.location.href = 'login.html';
        return;
    }

    let user;
    try {
        user = JSON.parse(sessionData);
    } catch (err) {
        console.error('Failed to parse user session:', err);
        window.location.href = 'login.html';
        return;
    }

    document.getElementById('profileName').innerText = user.first_name && user.last_name ? `${user.first_name} ${user.last_name}` : (user.email || 'Unknown');
    document.getElementById('profileEmail').innerText = user.email || 'Not available';
    document.getElementById('profilePhone').innerText = user.phone || 'Not available';
    document.getElementById('profileId').innerText = user.id || 'N/A';
}

window.addEventListener('load', function(){
    if(document.getElementById('reportList')){
        loadReports();
    }

    if(document.getElementById('profileInfo')){
        loadProfile();
    }
});