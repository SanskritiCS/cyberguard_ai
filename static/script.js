/* CyberGuard AI — Core Script v2.0 */

const API_BASE = window.location.origin;
let isDemoMode = false;
let globalBlocked = 17;
let globalScans = 42;

// File references for USB / Image modules
let usbFileRef = null;
let imageFileRef = null;

document.addEventListener("DOMContentLoaded", () => {
    if (window.lucide) lucide.createIcons();
    
    setTimeout(() => {
        document.getElementById("splash").classList.add("fade-out");
        document.getElementById("app").classList.remove("hidden");
        setTimeout(() => {
            document.getElementById("splash").style.display = 'none';
            animateHeroScore(92);
        }, 800);
    }, 2200);

    fetchIDS();
    setInterval(fetchIDS, 10000);
    startThreatFeed();
});

// ---- Demo Mode ----
function toggleDemoMode() {
    isDemoMode = !isDemoMode;
    const icon = document.getElementById("demo-icon");
    if (isDemoMode) {
        icon.classList.add("text-cyan");
        showToast("Demo Mode Enabled", "warning");
    } else {
        icon.classList.remove("text-cyan");
        showToast("Demo Mode Disabled — Live backend active", "safe");
    }
}

// ---- Toast Notifications ----
function showToast(message, type = "safe") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = "toast";
    const icons = { safe: "check-circle", warning: "alert-triangle", danger: "x-circle" };
    const colors = { safe: "var(--success)", warning: "var(--warning)", danger: "var(--danger)" };
    toast.innerHTML = `<i data-lucide="${icons[type] || 'info'}" style="color:${colors[type] || 'var(--text-main)'}; width:18px; height:18px"></i> <span>${message}</span>`;
    container.appendChild(toast);
    if (window.lucide) lucide.createIcons();
    setTimeout(() => { toast.style.opacity = "0"; setTimeout(() => toast.remove(), 300); }, 4000);
}

// ---- Navigation ----
function navigate(pageId, btnElement = null) {
    document.querySelectorAll(".page").forEach(p => p.classList.remove("active-page"));
    const target = document.getElementById(`page-${pageId}`);
    if (target) target.classList.add("active-page");
    
    const titles = {
        dashboard: 'Security Command Center', url: 'URL Scanner', qr: 'QR Scanner',
        email: 'Email Analyzer', sms: 'SMS Detector', voice: 'Voice Detector',
        usb: 'USB Threat Scanner', image: 'Image Authenticator',
        ids: 'Network IDS', history: 'Scan History', settings: 'Settings'
    };
    document.getElementById('page-title').innerText = titles[pageId] || 'CyberGuard AI';
    document.getElementById('page-subtitle').innerText = pageId === 'dashboard' ? 'AI Powered Cybersecurity Monitoring' : 'Detect → Explain → Warn → Protect';

    if (btnElement) {
        const parent = btnElement.closest('.sidebar-nav, .bottom-nav');
        if (parent) parent.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
        btnElement.classList.add("active");
    }
}

// ---- Dashboard Score Animation ----
function animateHeroScore(targetScore) {
    let current = parseInt(document.getElementById("global-score").innerText) || 0;
    if (current === targetScore) return;
    const increment = targetScore > current ? 1 : -1;
    const interval = setInterval(() => {
        current += increment;
        document.getElementById("global-score").innerText = current;
        document.getElementById("hero-circle-path").setAttribute("stroke-dasharray", `${current}, 100`);
        if (current === targetScore) clearInterval(interval);
    }, 18);
}

function updateGlobalStats(isThreat) {
    globalScans++;
    document.getElementById("stat-scans").innerText = globalScans;
    if (isThreat) {
        globalBlocked++;
        document.getElementById("stat-blocked").innerText = globalBlocked;
        animateHeroScore(Math.max(50, 100 - (globalBlocked * 2)));
    }
}

// ---- Explainable AI Result Builder ----
function buildExplainableUI(score, verdict, title, findings, recommendations) {
    let bgClass = "bg-safe", textClass = "text-green";
    if (verdict === "malicious" || score >= 70) { bgClass = "bg-critical"; textClass = "text-red"; updateGlobalStats(true); }
    else if (verdict === "suspicious" || score >= 40) { bgClass = "bg-high"; textClass = "text-warning"; updateGlobalStats(true); }
    else { updateGlobalStats(false); }

    const findingsHTML = findings.map(f => `<li><i data-lucide="info" style="width:16px;height:16px" class="text-cyan"></i> ${f}</li>`).join("");
    const recHTML = recommendations.map(r => `<div class="rec-item"><i data-lucide="check-circle" style="width:16px;height:16px" class="text-green"></i> ${r}</div>`).join("");

    return `
        <div class="result-block">
            <div class="result-header">
                <div><h3 class="mb-1 fw-semibold">${title}</h3><p class="text-muted text-sm">Analysis complete</p></div>
                <div><span class="risk-badge ${bgClass}">${score}/100 — ${verdict.toUpperCase()}</span></div>
            </div>
            <h4 class="mb-3 text-cyan text-sm fw-semibold" style="letter-spacing:1px">WHY WAS THIS FLAGGED?</h4>
            <div class="ai-explanation">
                <p>Based on our AI and heuristic analysis, here are the signals detected:</p>
                <ul class="findings-list mt-3">${findingsHTML}</ul>
            </div>
            <div class="recommendations-box"><h4>WHAT SHOULD YOU DO?</h4>${recHTML}</div>
        </div>
    `;
}

function showScanningState(containerId, message) {
    document.getElementById(containerId).innerHTML = `
        <div class="scanning-state">
            <div class="radar"></div>
            <h4 class="mt-4 mb-2 fw-semibold">Analyzing...</h4>
            <p class="text-muted text-sm">${message}</p>
        </div>`;
}

// ---- Dispatch Scanner ----
async function performScan(type) {
    if (type === 'url') await scanUrl();
    else if (type === 'email') await scanEmail();
    else if (type === 'sms') await scanSMS();
    else if (type === 'voice') await scanVoice();
    else if (type === 'usb') await scanUSB();
    else if (type === 'image') await scanImage();
}

// ---- URL Scanner ----
async function scanUrl() {
    const input = document.getElementById("url-input").value.trim();
    if (!input) return showToast("Please enter a URL.", "warning");
    showScanningState("url-results-container", "Analyzing URL structure, domain reputation, and ML signals...");
    try {
        let data;
        if (isDemoMode && input.includes("secure-bank-login")) {
            await sleep(1800);
            data = { score: 94, verdict: "malicious", findings: ["Possible impersonation of a banking institution.", "Domain uses a high-risk TLD.", "URL contains phishing-related keywords.", "Connection is not encrypted (no HTTPS)."] };
        } else {
            const res = await fetch(`${API_BASE}/scan-url`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: input }) });
            data = await res.json();
        }
        const recs = data.verdict === "safe"
            ? ["Proceed with caution.", "Always verify the site's SSL certificate."]
            : ["🚫 Do not open the link.", "🚫 Do not enter credentials.", "✅ Verify the sender independently.", "✅ Open the official website manually."];
        document.getElementById("url-results-container").innerHTML = buildExplainableUI(data.score, data.verdict, "URL Threat Analysis", data.findings, recs);
        if (window.lucide) lucide.createIcons();
    } catch (e) { showToast("Error connecting to backend", "danger"); document.getElementById("url-results-container").innerHTML = ""; }
}

// ---- Email Scanner ----
async function scanEmail() {
    const sender = document.getElementById("email-sender").value.trim();
    const subject = document.getElementById("email-subject").value.trim();
    const body = document.getElementById("email-body").value.trim();
    const fileInput = document.getElementById("email-file");
    if (!body && !subject) return showToast("Please paste an email body or subject.", "warning");
    showScanningState("email-results-container", "Analyzing email headers, language patterns, and attachments...");
    try {
        const formData = new FormData();
        formData.append("sender", sender); formData.append("subject", subject); formData.append("body", body);
        if (fileInput.files.length > 0) formData.append("attachment", fileInput.files[0]);
        const res = await fetch(`${API_BASE}/analyze-email`, { method: "POST", body: formData });
        const data = await res.json();
        let findings = [...data.email.findings];
        if (data.attachment) findings.push(`Attachment: ${data.attachment.findings[0]}`);
        if (data.ml_analysis) findings.push(`ML Model: ${data.ml_analysis.ml_prediction} (${data.ml_analysis.confidence}% confidence)`);
        const recs = data.verdict === "safe"
            ? ["Email appears legitimate, but double-check the sender.", "Do not click links if you did not expect this email."]
            : ["🚫 Do not click any links.", "🚫 Do not open attachments.", "✅ Mark as spam and delete.", "✅ Report to your IT department."];
        document.getElementById("email-results-container").innerHTML = buildExplainableUI(data.overall_score, data.verdict, "Email Risk Analysis", findings, recs);
        if (window.lucide) lucide.createIcons();
    } catch (e) { showToast("Error connecting to backend", "danger"); document.getElementById("email-results-container").innerHTML = ""; }
}

// ---- SMS Scanner ----
async function scanSMS() {
    const body = document.getElementById("sms-body").value.trim();
    if (!body) return showToast("Please paste an SMS.", "warning");
    showScanningState("sms-results-container", "Analyzing SMS for social engineering and scam patterns...");
    try {
        const res = await fetch(`${API_BASE}/analyze-sms`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ body }) });
        const data = await res.json();
        const recs = data.verdict === "safe"
            ? ["Verify the sender if unsure."]
            : ["🚫 Do not reply.", "🚫 Do not click any links.", "✅ Block the sender.", "✅ Report to your carrier."];
        document.getElementById("sms-results-container").innerHTML = buildExplainableUI(data.score, data.verdict, "SMS Scam Analysis", data.findings, recs);
        if (window.lucide) lucide.createIcons();
    } catch (e) { showToast("Error connecting to backend", "danger"); document.getElementById("sms-results-container").innerHTML = ""; }
}

// ---- Voice Scanner ----
async function scanVoice() {
    const fileInput = document.getElementById("voice-file");
    if (fileInput.files.length === 0) return showToast("Please upload an audio file.", "warning");
    showScanningState("voice-results-container", "Analyzing audio spectrum for synthetic generation patterns...");
    try {
        const formData = new FormData();
        formData.append("file", fileInput.files[0]);
        const res = await fetch(`${API_BASE}/analyze/voice`, { method: "POST", body: formData });
        const data = await res.json();
        const recs = data.verdict === "safe"
            ? ["No synthetic anomalies detected."]
            : ["🚫 Hang up immediately if on a call.", "✅ Establish a safe-word with family.", "🚫 Do not transfer funds based on voice requests alone."];
        document.getElementById("voice-results-container").innerHTML = buildExplainableUI(data.score, data.verdict, "AI Voice Analysis", data.findings, recs);
        if (window.lucide) lucide.createIcons();
    } catch (e) { showToast("Error connecting to backend", "danger"); document.getElementById("voice-results-container").innerHTML = ""; }
}

// ---- USB Scanner ----
function handleUSBDrop(event) {
    const files = event.dataTransfer.files;
    if (files.length > 0) {
        usbFileRef = files[0];
        document.getElementById("usb-file-name").innerText = `Selected: ${files[0].name} (${(files[0].size / 1024).toFixed(1)} KB)`;
        document.getElementById("usb-scan-btn").disabled = false;
    }
}
function handleUSBFile(input) {
    if (input.files.length > 0) {
        usbFileRef = input.files[0];
        document.getElementById("usb-file-name").innerText = `Selected: ${input.files[0].name} (${(input.files[0].size / 1024).toFixed(1)} KB)`;
        document.getElementById("usb-scan-btn").disabled = false;
    }
}
async function scanUSB() {
    if (!usbFileRef) return showToast("Please select a file to scan.", "warning");
    showScanningState("usb-results-container", "Scanning file for malware signatures, autorun exploits, and hidden scripts...");
    try {
        const formData = new FormData();
        formData.append("file", usbFileRef);
        const res = await fetch(`${API_BASE}/analyze-usb`, { method: "POST", body: formData });
        const data = await res.json();
        const recs = data.verdict === "safe"
            ? ["File appears safe to open.", "Keep your antivirus updated for real-time protection."]
            : ["🚫 Do not execute this file.", "✅ Delete the file from the USB device.", "✅ Run a full system scan.", "🚫 Do not allow autorun from untrusted devices."];
        document.getElementById("usb-results-container").innerHTML = buildExplainableUI(data.score, data.verdict, `USB File Analysis: ${data.filename}`, data.findings, recs);
        if (window.lucide) lucide.createIcons();
    } catch (e) { showToast("Error connecting to backend", "danger"); document.getElementById("usb-results-container").innerHTML = ""; }
}

// ---- Image Authenticator ----
function handleImageDrop(event) {
    const files = event.dataTransfer.files;
    if (files.length > 0) setImageFile(files[0]);
}
function handleImageFile(input) {
    if (input.files.length > 0) setImageFile(input.files[0]);
}
function setImageFile(file) {
    imageFileRef = file;
    document.getElementById("image-file-name").innerText = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    document.getElementById("image-scan-btn").disabled = false;
    // Preview
    const reader = new FileReader();
    reader.onload = (e) => {
        const preview = document.getElementById("image-preview");
        preview.src = e.target.result;
        preview.classList.remove("hidden");
    };
    reader.readAsDataURL(file);
}
async function scanImage() {
    if (!imageFileRef) return showToast("Please select an image.", "warning");
    showScanningState("image-results-container", "Analyzing image…<br>Checking visual patterns and authenticity signals…");
    try {
        const formData = new FormData();
        formData.append("file", imageFileRef);
        const res = await fetch(`${API_BASE}/analyze-image`, { method: "POST", body: formData });
        const data = await res.json();

        if (data.error) {
            showToast(data.error, "danger");
            document.getElementById("image-results-container").innerHTML = "";
            return;
        }

        // Classification info
        const classification = data.classification || "Inconclusive";
        const confidence = data.confidence ?? 50;
        const riskLevel = data.risk_level || "Medium";
        const explanation = data.explanation || "Analysis complete.";
        const signals = data.signals || [];
        const analysisMethod = data.analysis_method || "unknown";

        // Emoji and color mapping
        const classMap = {
            "Likely Real": { emoji: "🟢", color: "var(--success)", badgeClass: "bg-safe" },
            "Likely AI-Generated": { emoji: "🟠", color: "var(--warning)", badgeClass: "bg-high" },
            "Likely Manipulated": { emoji: "🔴", color: "var(--danger)", badgeClass: "bg-critical" },
            "Inconclusive": { emoji: "🔵", color: "var(--primary)", badgeClass: "bg-high" },
        };
        const cm = classMap[classification] || classMap["Inconclusive"];

        const riskMap = {
            "Low": { color: "var(--success)", text: "LOW" },
            "Medium": { color: "var(--warning)", text: "MEDIUM" },
            "High": { color: "var(--danger)", text: "HIGH" },
        };
        const rm = riskMap[riskLevel] || riskMap["Medium"];

        // Build signals list
        const signalsHTML = signals.length > 0
            ? signals.map(s => `<li><i data-lucide="info" style="width:16px;height:16px" class="text-cyan"></i> ${s}</li>`).join("")
            : '<li class="text-muted">No specific signals reported.</li>';

        // Build EXIF table
        let exifHTML = "";
        if (data.exif && Object.keys(data.exif).length > 0) {
            const rows = Object.entries(data.exif)
                .filter(([k, v]) => v && v !== "false" && v !== "")
                .map(([k, v]) => `<tr><td class="fw-medium text-muted">${k.replace(/_/g, ' ')}</td><td>${v}</td></tr>`)
                .join("");
            if (rows) exifHTML = `<div class="card mt-4 p-5"><h4 class="mb-3 fw-semibold text-sm" style="letter-spacing:1px;text-transform:uppercase">Image Metadata</h4><table class="exif-table">${rows}</table></div>`;
        }

        // Heuristic findings (supplementary)
        const findings = data.findings || [];
        const findingsHTML = findings.length > 0
            ? `<div class="recommendations-box mt-4"><h4>HEURISTIC FINDINGS</h4>${findings.map(f => `<div class="rec-item"><i data-lucide="search" style="width:16px;height:16px" class="text-muted"></i> ${f}</div>`).join("")}</div>`
            : "";

        const resultHTML = `
            <div class="result-block">
                <div class="result-header">
                    <div>
                        <h3 class="mb-1 fw-semibold">Image Analysis Result</h3>
                        <p class="text-muted text-sm">File: ${data.filename || imageFileRef.name}</p>
                    </div>
                    <div style="text-align:right">
                        <span class="risk-badge ${cm.badgeClass}" style="font-size:1rem">${cm.emoji} ${classification}</span>
                    </div>
                </div>

                <div class="flex gap-6 mb-6" style="flex-wrap:wrap">
                    <div style="flex:1;min-width:140px">
                        <p class="text-muted text-xs fw-semibold mb-1" style="letter-spacing:1px;text-transform:uppercase">Confidence</p>
                        <p style="font-size:2rem;font-weight:800;color:${cm.color}">${confidence}%</p>
                    </div>
                    <div style="flex:1;min-width:140px">
                        <p class="text-muted text-xs fw-semibold mb-1" style="letter-spacing:1px;text-transform:uppercase">Risk Level</p>
                        <p style="font-size:1.25rem;font-weight:700;color:${rm.color}">${rm.text}</p>
                    </div>
                    <div style="flex:2;min-width:200px">
                        <p class="text-muted text-xs fw-semibold mb-1" style="letter-spacing:1px;text-transform:uppercase">Analysis</p>
                        <p class="text-sm">${explanation}</p>
                    </div>
                </div>

                <h4 class="mb-3 text-cyan text-sm fw-semibold" style="letter-spacing:1px">DETECTION SIGNALS</h4>
                <div class="ai-explanation">
                    <ul class="findings-list">${signalsHTML}</ul>
                </div>

                ${findingsHTML}

                <div style="margin-top:1.25rem;padding:0.75rem 1rem;background:rgba(255,255,255,0.02);border-radius:var(--radius-sm);border:1px dashed rgba(255,255,255,0.08)">
                    <p class="text-muted text-xs" style="line-height:1.5">
                        <i data-lucide="info" style="width:14px;height:14px;display:inline;vertical-align:-2px" class="mr-2"></i>
                        AI-image detection is probabilistic and should not be treated as definitive proof. 
                        Analysis method: ${analysisMethod === "gemini_vision" ? "Gemini Vision AI" : "Heuristic only"}.
                    </p>
                </div>
            </div>
        `;

        document.getElementById("image-results-container").innerHTML = resultHTML + exifHTML;
        if (window.lucide) lucide.createIcons();
        updateGlobalStats(classification !== "Likely Real");
    } catch (e) {
        console.error("Image scan error:", e);
        showToast("Error connecting to backend", "danger");
        document.getElementById("image-results-container").innerHTML = "";
    }
}

// ---- QR Camera ----
let qrStream = null;
async function startQRCamera() {
    const video = document.getElementById('qr-video');
    const placeholder = document.getElementById('qr-placeholder');
    const scanLine = document.getElementById('qr-scan-line');
    try {
        qrStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
        video.srcObject = qrStream; video.play();
        video.classList.remove('hidden'); scanLine.classList.remove('hidden'); placeholder.classList.add('hidden');
        setInterval(captureQRFrame, 3000);
    } catch (err) { showToast("Camera access denied or unavailable.", "danger"); }
}
async function captureQRFrame() {
    if (!qrStream) return;
    const video = document.getElementById('qr-video');
    const canvas = document.createElement('canvas');
    canvas.width = video.videoWidth; canvas.height = video.videoHeight;
    canvas.getContext('2d').drawImage(video, 0, 0);
    canvas.toBlob(async (blob) => {
        const formData = new FormData(); formData.append("file", blob, "frame.jpg");
        try {
            const res = await fetch(`${API_BASE}/scan/camera`, { method: "POST", body: formData });
            const data = await res.json();
            if (data.qr_detected && data.content_type === "url") {
                qrStream.getTracks().forEach(t => t.stop()); qrStream = null;
                document.getElementById('qr-video').classList.add('hidden');
                document.getElementById('qr-scan-line').classList.add('hidden');
                document.getElementById('qr-placeholder').classList.remove('hidden');
                const recs = data.verdict === "safe" ? ["Proceed to the destination safely."] : ["🚫 Do not open the destination link.", "✅ Verify QR code hasn't been tampered with."];
                document.getElementById("qr-results-container").innerHTML = buildExplainableUI(data.score, data.verdict, `QR Destination: ${data.decoded}`, data.findings, recs);
                if (window.lucide) lucide.createIcons();
            }
        } catch (e) {}
    }, 'image/jpeg');
}
async function uploadQR(inputElement) {
    if (inputElement.files.length === 0) return;
    showScanningState("qr-results-container", "Decoding image and analyzing destination...");
    try {
        const formData = new FormData(); formData.append("file", inputElement.files[0]);
        const res = await fetch(`${API_BASE}/scan/qr`, { method: "POST", body: formData });
        const data = await res.json();
        if (!data.decoded) { showToast("No QR code found in image.", "warning"); document.getElementById("qr-results-container").innerHTML = ""; return; }
        const recs = (data.verdict || "unknown") === "safe" ? ["Proceed safely."] : ["🚫 Do not open the destination link."];
        document.getElementById("qr-results-container").innerHTML = buildExplainableUI(data.score || 0, data.verdict || "unknown", `QR Destination: ${data.decoded}`, data.findings || ["Decoded successfully."], recs);
        if (window.lucide) lucide.createIcons();
    } catch (e) { showToast("Error connecting to backend", "danger"); document.getElementById("qr-results-container").innerHTML = ""; }
}

// ---- AI Assistant ----
function toggleAI() { document.getElementById("ai-widget").classList.toggle("hidden"); }

async function sendAIMessage() {
    const input = document.getElementById("ai-input");
    const msg = input.value.trim();
    if (!msg) return;
    appendChatBubble(msg, "user"); input.value = "";
    appendChatBubble("Thinking...", "bot", "typing-indicator");
    try {
        let replyText;
        if (isDemoMode) {
            await sleep(1000);
            replyText = "Phishing is a cyber attack where attackers impersonate trusted entities to trick you into revealing passwords or bank details. Use our URL Scanner to check suspicious links.";
        } else {
            const res = await fetch(`${API_BASE}/ask-ai`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ message: msg }) });
            const data = await res.json();
            replyText = data.reply;
        }
        const typing = document.getElementById("typing-indicator");
        if (typing) typing.remove();
        appendChatBubble(replyText, "bot");
    } catch (e) {
        const typing = document.getElementById("typing-indicator");
        if (typing) typing.remove();
        appendChatBubble("I couldn't connect to my knowledge base right now.", "bot");
    }
}
function appendChatBubble(text, sender, id = "") {
    const chatBody = document.getElementById("ai-chat-history");
    const bubble = document.createElement("div");
    bubble.className = `chat-bubble ${sender}`;
    if (id) bubble.id = id;
    // Simple markdown rendering for bold
    bubble.innerHTML = text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    chatBody.appendChild(bubble);
    chatBody.scrollTop = chatBody.scrollHeight;
}

// ---- Network IDS ----
async function fetchIDS() {
    if (isDemoMode) return;
    try {
        const res = await fetch(`${API_BASE}/ids-status`);
        const data = await res.json();
        document.getElementById("ids-meta").innerText = `Rules: ${data.rules_loaded} | Engine: ${data.engine} (${data.engine_status}) | Uptime: ${Math.floor(data.uptime_sec / 60)}m`;
        const tbody = document.querySelector("#ids-table tbody"); tbody.innerHTML = "";
        data.alerts.forEach(alert => {
            const tr = document.createElement("tr");
            const bc = alert.severity === 1 ? "bg-critical" : (alert.severity === 2 ? "bg-high" : "bg-safe");
            const st = alert.severity === 1 ? "CRITICAL" : (alert.severity === 2 ? "HIGH" : "LOW");
            tr.innerHTML = `<td>${new Date(alert.timestamp).toLocaleTimeString()}</td><td>${alert.src_ip}</td><td>${alert.dest_ip}:${alert.dest_port}</td><td>${alert.signature}</td><td><span class="risk-badge text-xs ${bc}">${st}</span></td>`;
            tbody.appendChild(tr);
        });
        if (window.lucide) lucide.createIcons();
    } catch (e) { console.warn("IDS fetch failed"); }
}

// ---- Live Threat Feed ----
const mockThreats = [
    { text: "Phishing URL detected", color: "var(--danger)" },
    { text: "Suspicious QR analyzed", color: "var(--warning)" },
    { text: "Email threat blocked", color: "var(--danger)" },
    { text: "Network anomaly detected", color: "var(--warning)" },
    { text: "System scan completed", color: "var(--success)" },
    { text: "USB file flagged", color: "var(--danger)" },
    { text: "AI image scan complete", color: "var(--success)" },
];
function startThreatFeed() {
    const feed = document.getElementById("live-threat-feed");
    if (!feed) return;
    setInterval(() => {
        const t = mockThreats[Math.floor(Math.random() * mockThreats.length)];
        const item = document.createElement("div");
        item.className = "feed-item";
        item.style.borderLeftColor = t.color;
        item.innerHTML = `<span class="text-muted text-xs">${new Date().toLocaleTimeString()}</span> <span class="text-sm">${t.text}</span>`;
        feed.prepend(item);
        if (feed.children.length > 6) feed.lastElementChild.remove();
    }, 4500);
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }