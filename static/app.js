const $ = (selector) => document.querySelector(selector);

const createView = $("#createView");
const openView = $("#openView");
const dashboardView = $("#dashboardView");
const message = $("#message");
const fileInput = $("#fileInput");

let currentShareId = null;
let currentSenderToken = null;
let currentStatus = null;

function show(view) {
  [createView, openView, dashboardView].forEach((item) => item.classList.add("hidden"));
  view.classList.remove("hidden");
}

function setMessage(text, error = false) {
  message.textContent = text || "";
  message.style.color = error ? "#ffd9de" : "#dcfff8";
}

async function api(path, payload) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  if (!response.ok || data.error) throw new Error(data.error || "Request failed");
  return data;
}

function pathParts() {
  return location.pathname.split("/").filter(Boolean);
}

function initRoute() {
  const parts = pathParts();
  if (parts[0] === "s" && parts[1]) {
    currentShareId = parts[1];
    show(openView);
    loadOpenStatus();
    return;
  }
  if (parts[0] === "d" && parts[1] && parts[2]) {
    currentShareId = parts[1];
    currentSenderToken = parts[2];
    show(dashboardView);
    loadDashboard();
    return;
  }
  show(createView);
}

fileInput?.addEventListener("change", () => {
  $("#fileName").textContent = fileInput.files[0]?.name || "Choose file";
});

$("#createBtn")?.addEventListener("click", async () => {
  try {
    setMessage("Creating secure link...");
    const file = fileInput.files[0];
    const password = $("#createPassword").value;
    if (!file) throw new Error("Choose a file.");
    if (password.length < 8) throw new Error("Password must be at least 8 characters.");
    const buffer = await file.arrayBuffer();
    const file_b64 = arrayBufferToBase64(buffer);
    const result = await api("/api/create", {
      filename: file.name,
      mime: file.type || "application/octet-stream",
      file_b64,
      password,
      expiry_hours: Number($("#expiryHours").value),
      mode: $("#accessMode").value,
    });
    $("#shareUrl").value = result.share_url;
    $("#dashboardUrl").value = result.dashboard_url;
    $("#createResult").classList.remove("hidden");
    setMessage("Link created.");
  } catch (error) {
    setMessage(error.message, true);
  }
});

async function loadOpenStatus() {
  try {
    currentStatus = await api("/api/status", { id: currentShareId });
    $("#openTitle").textContent = currentStatus.filename;
    renderMeta($("#openMeta"), currentStatus);
    $("#previewBtn").disabled =
      !["preview", "either"].includes(currentStatus.mode) ||
      currentStatus.status !== "active" ||
      !isPreviewSupported(currentStatus.filename, currentStatus.mime);
    $("#downloadBtn").disabled = !["download", "either"].includes(currentStatus.mode) || currentStatus.status !== "active";
    if (currentStatus.status === "active" && currentStatus.mode === "preview" && !isPreviewSupported(currentStatus.filename, currentStatus.mime)) {
      setMessage("Preview is not supported for this file type.", true);
    }
  } catch (error) {
    setMessage(error.message, true);
  }
}

$("#previewBtn")?.addEventListener("click", () => openShare("preview"));
$("#downloadBtn")?.addEventListener("click", () => openShare("download"));

async function openShare(action) {
  try {
    setMessage(action === "preview" ? "Opening..." : "Downloading...");
    const result = await api("/api/open", {
      id: currentShareId,
      password: $("#openPassword").value,
      action,
    });
    const bytes = base64ToBytes(result.content_b64);
    const blob = new Blob([bytes], { type: result.mime });
    if (action === "download") {
      downloadBlob(blob, result.filename);
      $("#previewBox").classList.add("hidden");
    } else {
      renderPreview(blob, result);
    }
    setMessage("This share has vanished.");
    await loadOpenStatus();
  } catch (error) {
    setMessage(error.message, true);
  }
}

async function loadDashboard() {
  try {
    currentStatus = await api("/api/status", { id: currentShareId, sender_token: currentSenderToken });
    $("#dashTitle").textContent = currentStatus.filename;
    renderStats(currentStatus);
    renderAudit(currentStatus.audit || []);
    $("#revokeBtn").disabled = currentStatus.status !== "active";
  } catch (error) {
    setMessage(error.message, true);
  }
}

$("#revokeBtn")?.addEventListener("click", async () => {
  try {
    setMessage("Revoking...");
    await api("/api/revoke", { id: currentShareId, sender_token: currentSenderToken });
    setMessage("Access revoked.");
    await loadDashboard();
  } catch (error) {
    setMessage(error.message, true);
  }
});

function renderMeta(target, status) {
  target.innerHTML = "";
  const items = [
    status.status,
    status.mode,
    `expires ${status.expires_at}`,
    `${formatBytes(status.size)}`,
  ];
  for (const item of items) {
    const pill = document.createElement("span");
    pill.className = `pill ${status.status === "active" ? "" : "warn"}`;
    pill.textContent = item;
    target.append(pill);
  }
}

function renderStats(status) {
  $("#dashStats").innerHTML = [
    ["Status", status.status],
    ["Expires", status.expires_at],
    ["Failed attempts", status.failed_attempts],
    ["Opened", status.opened_at || "-"],
    ["Action", status.opened_action || "-"],
    ["Size", formatBytes(status.size)],
  ]
    .map(([label, value]) => `<div class="stat"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`)
    .join("");
}

function renderAudit(items) {
  $("#auditLog").innerHTML = items.length
    ? items
        .map(
          (item) =>
            `<div class="audit-item"><strong>${escapeHtml(item.event)}</strong><span>${escapeHtml(item.created_at)}</span></div>`
        )
        .join("")
    : '<div class="audit-item"><strong>No events</strong><span>-</span></div>';
}

function renderPreview(blob, result) {
  const box = $("#previewBox");
  box.classList.remove("hidden");
  box.innerHTML = "";
  const url = URL.createObjectURL(blob);
  if (result.mime.startsWith("image/")) {
    const img = document.createElement("img");
    img.src = url;
    box.append(img);
  } else if (result.mime === "application/pdf") {
    const frame = document.createElement("iframe");
    frame.src = url;
    box.append(frame);
  } else if (result.mime.startsWith("text/") || result.filename.match(/\.(txt|md|csv|json|py|js|html|css)$/i)) {
    blob.text().then((text) => {
      const pre = document.createElement("pre");
      pre.className = "preview-text";
      pre.textContent = text;
      box.append(pre);
    });
  } else {
    box.textContent = "Preview is not supported for this file type.";
  }
}

function isPreviewSupported(filename, mime) {
  return (
    mime.startsWith("image/") ||
    mime === "application/pdf" ||
    mime.startsWith("text/") ||
    /\.(txt|md|csv|json|py|js|html|css)$/i.test(filename)
  );
}

function arrayBufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64ToBytes(text) {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB"];
  let value = bytes;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(index ? 1 : 0)} ${units[index]}`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

initRoute();
