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

  // Redirect to login page
  window.location.href = 'login.html';
}

function getCurrentUser() {
    const sessionData = localStorage.getItem('user_session') || sessionStorage.getItem('user_session');
    if (!sessionData) return null;

    try {
        return JSON.parse(sessionData);
    } catch (err) {
        console.error('Failed to parse user session:', err);
        return null;
    }
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

/* CAMERA */
function openCamera(){
    const input = document.createElement("input");
    input.type = "file";
    input.accept = "image/*";
    input.capture = "environment";

    input.onchange = e => {
        const file = e.target.files[0];
        const reader = new FileReader();

        reader.onload = function(){
            imageData = reader.result;

            document.getElementById("previewBox").innerHTML =
                `<img src="${imageData}">`;
        };

        reader.readAsDataURL(file);
    };

    input.click();
}

/* IMAGE SOURCE CHOICE */
function chooseImageSource() {
    const choice = confirm("How would you like to add an image?\n\nOK = Take Photo with Camera\nCancel = Choose from Gallery");

    if (choice) {
        // Open camera
        console.log("Opening camera...");
        openCameraWithCapture();
    } else {
        // Choose from local storage
        console.log("Opening file picker...");
        openFilePicker();
    }
}

/* CAMERA */
function openCamera(){
    const input = document.createElement("input");
    input.type = "file";
    input.accept = "image/*";
    input.capture = "environment";

    input.onchange = e => {
        const file = e.target.files[0];
        const reader = new FileReader();

        reader.onload = function(){
            imageData = reader.result;

            document.getElementById("previewBox").innerHTML =
                `<img src="${imageData}">`;
        };

        reader.readAsDataURL(file);
    };

    input.click();
}

/* CAMERA WITH CAPTURE */
function openCameraWithCapture(){
    console.log("Opening camera with MediaDevices API...");

    // Check if camera is supported
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        alert("Camera not supported on this device/browser");
        return;
    }

    // Create camera interface
    const cameraContainer = document.createElement('div');
    cameraContainer.id = 'cameraContainer';
    cameraContainer.innerHTML = `
        <div style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; display: flex; flex-direction: column; align-items: center; justify-content: center;">
            <video id="cameraVideo" autoplay playsinline style="max-width: 90%; max-height: 70%; border: 2px solid white;"></video>
            <div style="margin-top: 20px;">
                <button id="captureBtn" style="padding: 10px 20px; margin: 0 10px; background: #4CAF50; color: white; border: none; border-radius: 5px; cursor: pointer;">📷 Capture</button>
                <button id="cancelBtn" style="padding: 10px 20px; margin: 0 10px; background: #f44336; color: white; border: none; border-radius: 5px; cursor: pointer;">❌ Cancel</button>
            </div>
        </div>
    `;
    document.body.appendChild(cameraContainer);

    const video = document.getElementById('cameraVideo');
    const captureBtn = document.getElementById('captureBtn');
    const cancelBtn = document.getElementById('cancelBtn');

    // Start camera
    navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
        .then(stream => {
            video.srcObject = stream;
            console.log("Camera stream started");
        })
        .catch(err => {
            console.error("Camera access denied:", err);
            alert("Camera access denied. Please allow camera permissions and try again.");
            document.body.removeChild(cameraContainer);
        });

    // Capture photo
    captureBtn.onclick = () => {
        const canvas = document.createElement('canvas');
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(video, 0, 0);

        // Convert to base64
        imageData = canvas.toDataURL('image/jpeg', 0.8);
        console.log("Photo captured:", imageData.substring(0, 50) + "...");

        // Stop camera stream
        const stream = video.srcObject;
        if (stream) {
            stream.getTracks().forEach(track => track.stop());
        }

        // Update preview
        document.getElementById("previewBox").innerHTML = `<img src="${imageData}">`;

        // Remove camera interface
        document.body.removeChild(cameraContainer);
    };

    // Cancel camera
    cancelBtn.onclick = () => {
        // Stop camera stream
        const stream = video.srcObject;
        if (stream) {
            stream.getTracks().forEach(track => track.stop());
        }

        // Remove camera interface
        document.body.removeChild(cameraContainer);
    };
}

/* FILE PICKER */
function openFilePicker(){
    const input = document.createElement("input");
    input.type = "file";
    input.accept = "image/*";

    input.onchange = e => {
        const file = e.target.files[0];
        const reader = new FileReader();

        reader.onload = function(){
            imageData = reader.result;

            document.getElementById("previewBox").innerHTML =
                `<img src="${imageData}">`;
        };

        reader.readAsDataURL(file);
    };

    input.click();
}

/* GPS */
function getLocation(){
    navigator.geolocation.getCurrentPosition(pos => {
        gpsData = pos.coords.latitude + ", " + pos.coords.longitude;

        document.getElementById("gpsBox").innerText =
            "GPS: " + gpsData;
    });
}

/* CLEAR FORM - FIXED (Added this function) */
function clearForm(){
    // Clear textarea
    const descInput = document.getElementById("description");
    if(descInput) descInput.value = "";
    
    // Clear image
    imageData = "";
    const previewBox = document.getElementById("previewBox");
    if(previewBox) previewBox.innerHTML = "";
    
    // Clear GPS
    gpsData = "";
    const gpsBox = document.getElementById("gpsBox");
    if(gpsBox) gpsBox.innerText = "";
    
    console.log("Form cleared successfully");
}

function submitReport(){
    const desc = document.getElementById("description").value;

    if(!desc){
        alert("Please describe the issue");
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
    fetch('http://localhost:3000/submit-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(report)
    })
    .then(res => res.json())
    .then(data => {
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

/* SHOW REPORTS */
function loadReports(){
    const user = getCurrentUser();
    if(!user){
        window.location.href = 'login.html';
        return;
    }

    fetch(`http://localhost:3000/my-reports/${user.id}`)
    .then(res => res.json())
    .then(reports => {
        const list = document.getElementById("reportList");
        if(!list) return;

        list.innerHTML = "";

        if(reports.length === 0){
            list.innerHTML = `<div class="report-box">No reports submitted yet</div>`;
            return;
        }

        reports.forEach(report => {
            let div = document.createElement("div");
            div.className = "report-box";
            div.innerHTML = `
                <p><strong>Issue:</strong> ${report.description}</p>
                <p><strong>Date:</strong> ${new Date(report.date).toLocaleString('en-ZA', {timeZone: 'Africa/Johannesburg'})}</p>
                <p><strong>Location:</strong> ${report.location || "Not provided"}</p>
                <p><strong>Status:</strong> ${report.status} ⏳</p>
            `;
            list.appendChild(div);
        });
    })
    .catch(err => {
        console.error(err);
    });
}

/* CLEAR REPORTS */
function clearReports(){
    const user = getCurrentUser();
    if(!user){
        window.location.href = 'login.html';
        return;
    }

    if(confirm("Are you sure you want to clear all reports? This cannot be undone.")){
        fetch(`http://localhost:3000/clear-reports/${user.id}`, {
            method: 'DELETE'
        })
        .then(res => res.json())
        .then(data => {
            if(data.message === "Reports cleared successfully"){
                loadReports(); // refresh the list
                alert("All reports cleared.");
            } else {
                alert("Failed to clear: " + data.message);
            }
        })
        .catch(err => {
            console.error(err);
            alert("Could not connect to server.");
        });
    }
}

function loadProfile(){
    const sessionData = localStorage.getItem('user_session') || sessionStorage.getItem('user_session');
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