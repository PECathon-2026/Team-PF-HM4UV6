/* ==========================================
   PrivacyLens — JavaScript
   Local privacy scanner + sensitive-content alerts
   ========================================== */

"use strict";

// ---------- DOM ELEMENTS ----------

const sourceText = document.getElementById("source-text");
const scanForm = document.getElementById("scan-form");
const scanContext = document.getElementById("scan-context");
const findingSummary = document.getElementById("finding-summary");
const loadSampleButton = document.getElementById("load-sample");
const clearFormButton = document.getElementById("clear-form");
const imageUpload = document.getElementById("image-upload");
const scanImageButton = document.getElementById("scan-image");
const textFindInput = document.getElementById("text-find-input");
const findInTextButton = document.getElementById("find-in-text");
const textFindStatus = document.getElementById("text-find-status");
const protectedPreview = document.getElementById("original-output");
const sanitizedOutput = document.getElementById("sanitized-output");
const scanStatus = document.getElementById("scan-status");
const sendSecurelyButton = document.getElementById("send-securely");
const sendStatus = document.getElementById("send-status");

const activityRows = document.getElementById("activity-rows");
const clearLogButton = document.getElementById("clear-log");

const detectedCount = document.getElementById("detected-count");
const protectionStatus = document.getElementById("protection-status");
const sensitiveAlert = document.getElementById("sensitive-alert");
const sensitiveAlertMessage = document.getElementById("sensitive-alert-message");

// ---------- APPLICATION STATE ----------

let currentDetectionCount = 0;
let activity = [];
let scanGeneration = 0;
let lastScannedText = null;
let scanRecordId = null;
let sending = false;
const MAX_TEXT_CHARS = 100000;
const API_BASE_URL = (() => {
  const { hostname, port, protocol } = window.location;
  const isLocalHost = ["localhost", "127.0.0.1", "::1"].includes(hostname);

  if (protocol === "file:") return "http://127.0.0.1:8000";
  if (isLocalHost && port !== "8000") return "http://127.0.0.1:8000";
  return "";
})();

// ---------- GENERAL HELPERS ----------

function setStatus(element, message, type = "") {
  if (!element) return;

  element.textContent = message;
  element.classList.remove("success", "danger", "warning", "is-scanning");

  if (type) {
    element.classList.add(type);
  }
}

function showSensitivePopup(message) {
  if (!sensitiveAlert || !sensitiveAlertMessage) return;

  sensitiveAlertMessage.textContent = message;

  if (!sensitiveAlert.open) {
    sensitiveAlert.showModal();
  }
}

function updateDashboard() {
  if (detectedCount) {
    detectedCount.textContent = currentDetectionCount;
  }

  if (protectionStatus) {
    protectionStatus.textContent = "READY";
    protectionStatus.title =
      "Sensitive-content warnings appear when the scanner reports a match.";
  }
}

function addActivity(action, result, details) {
  const entry = {
    time: new Date().toLocaleTimeString(),
    action,
    result,
    details
  };

  activity.unshift(entry);
  activity = activity.slice(0, 30);

  renderActivity();
}

function renderActivity() {
  if (!activityRows) return;

  activityRows.replaceChildren();

  if (activity.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");

    cell.colSpan = 4;
    cell.textContent = "No activity yet. Run a scan to begin.";
    cell.className = "empty-state";

    row.appendChild(cell);
    activityRows.appendChild(row);
    return;
  }

  activity.forEach((entry) => {
    const row = document.createElement("tr");

    [entry.time, entry.action, entry.result, entry.details]
      .forEach((value) => {
        const cell = document.createElement("td");
        cell.textContent = value;
        row.appendChild(cell);
      });

    activityRows.appendChild(row);
  });
}

function playDetectionWarning() {
  try {
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    if (!AudioContext) return;

    const audioContext = new AudioContext();
    const oscillator = audioContext.createOscillator();
    const volume = audioContext.createGain();
    const now = audioContext.currentTime;

    oscillator.type = "sine";
    oscillator.frequency.setValueAtTime(740, now);
    oscillator.frequency.exponentialRampToValueAtTime(520, now + 0.16);
    volume.gain.setValueAtTime(0.0001, now);
    volume.gain.exponentialRampToValueAtTime(0.045, now + 0.015);
    volume.gain.exponentialRampToValueAtTime(0.0001, now + 0.18);

    oscillator.connect(volume);
    volume.connect(audioContext.destination);
    oscillator.start(now);
    oscillator.stop(now + 0.19);
    oscillator.addEventListener("ended", () => audioContext.close(), { once: true });
  } catch {
    // Audio is optional; scanning must work even when playback is unavailable.
  }
}

// ---------- SERVER-AUTHORITATIVE SCANNING ----------

function renderProtectedPreview(segments) {
  if (!protectedPreview || !sanitizedOutput) return;

  protectedPreview.replaceChildren();
  sanitizedOutput.textContent = "";

  let detectedCount = 0;
  (segments || []).forEach((segment) => {
    const text = typeof segment.text === "string" ? segment.text : "";

    if (segment.kind === "finding") {
      const mark = document.createElement("mark");
      mark.className = "detected-span";
      const finding = segment.finding || {};
      mark.textContent = `[REDACTED: ${finding.category || "sensitive information"}]`;
      mark.title = `${finding.category || "Sensitive data"} / ${finding.severity || "review"} / ${Math.round((finding.confidence || 0) * 100)}% confidence`;
      protectedPreview.appendChild(mark);
      sanitizedOutput.appendChild(document.createTextNode("[REDACTED]"));
      detectedCount++;
    } else {
      sanitizedOutput.appendChild(document.createTextNode(text));
    }
  });
  if (!detectedCount) {
    protectedPreview.textContent = "No configured sensitive values were detected.";
  }
}

function renderFindingSummary(findings, state) {
  if (!findingSummary) return;
  findingSummary.replaceChildren();

  if (!findings.length) {
    if (state !== "no_matches_unverified") return;

    const message = document.createElement("p");
    message.textContent = "No configured sensitive patterns matched. Other sensitive content may not be detected.";
    findingSummary.appendChild(message);
    return;
  }

  const list = document.createElement("ul");
  list.className = "finding-list";
  findings.forEach((finding) => {
    const item = document.createElement("li");
    item.className = "finding-item";

    const category = document.createElement("span");
    category.className = "finding-category";
    const categoryCodes = {
      "Payment card": "CC",
      "Payment credential": "CVV",
      "Authentication secret": "KEY",
      "API key or token": "KEY",
      "Email address": "@",
      "Phone number": "TEL",
      "Personal name": "NAME",
      "Home address": "ADDR",
      "Bank account details": "FIN",
      "Banking code": "BANK",
      "Banking identifier": "BANK",
      "Aadhaar number": "AAD",
      "PAN number": "PAN",
      "Personal identifier": "ID",
      "Date of birth": "DOB",
      "Government identifier": "ID",
      "Student or employee identifier": "ID",
      "Personal information": "PII",
      "Financial information": "FIN",
      "Health or biometric information": "HLT",
      "Confidential information": "CONF",
      "Institution identifier": "ORG"
    };
    const icon = document.createElement("span");
    icon.className = "finding-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = categoryCodes[finding.category] || "DLP";
    category.appendChild(icon);
    category.appendChild(document.createTextNode(finding.correlated
      ? `${finding.category} / correlated identifiers`
      : finding.category));

    const risk = document.createElement("span");
    const severity = ["critical", "high", "medium", "low"].includes(finding.severity)
      ? finding.severity
      : "medium";
    risk.className = `finding-risk severity-${severity}`;
    risk.textContent = `${finding.severity} / ${Math.round(finding.confidence * 100)}%`;

    const action = document.createElement("span");
    action.className = "finding-action";
    action.textContent = finding.action;

    item.append(category, risk, action);
    list.appendChild(item);
  });
  findingSummary.appendChild(list);
}

const FALLBACK_RULES = [
  { pattern: /\b(?:aadhaar|aadhar|uidai)(?:\s+(?:card|number|no\.?|id))?\b\s*(?::|=|\bis\b)?\s*((?:\d[ \t.-]?){11}\d)(?!\d)/gi, category: "Aadhaar number", priority: 110, confidence: 0.99 },
  { pattern: /(?<![\w])(?:\d[ \t.-]?){11}\d(?![\w])/g, category: "Aadhaar number", priority: 85, confidence: 0.95 },
  { pattern: /\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b/gi, category: "PAN number", priority: 105, confidence: 0.99 },
  { pattern: /\b(?:ifsc(?:\s+code)?|swift(?:\s+code)?|bic)\b\s*(?::|=|\bis\b)?\s*([A-Z]{4}0[A-Z0-9]{6}|[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b/gi, category: "Banking code", priority: 105, confidence: 0.99 },
  { pattern: /\b(?:upi\s+(?:id|address)|vpa)\b\s*(?::|=|\bis\b)?\s*([A-Z0-9._-]+@[A-Z0-9.-]+)\b/gi, category: "Banking identifier", priority: 110, confidence: 0.97 },
  { pattern: /\b[A-Z]{2}\d{2}(?:[ \t]?[A-Z0-9]){11,30}\b/gi, category: "Bank account details", priority: 100, confidence: 0.98 },
  { pattern: /\b(?:password|passwd|passcode|pin)\b\s*(?::|=|\bis\b)\s*([^\r\n,;]{2,})/gi, category: "Authentication secret", priority: 100, confidence: 0.99 },
  { pattern: /\b(?:cvv|cvc|security\s+code)\b\s*(?::|=|\bis\b)?\s*(\d{3,4})\b/gi, category: "Payment credential", priority: 100, confidence: 0.99 },
  { pattern: /\b(?:(?:credit|debit)\s+)?card\s+(?:number|details|info)\b\s*(?::|=|\bis\b)?\s*(\d(?:[ \t.-]?\d){12,18})(?!\d)/gi, category: "Payment card", priority: 110, confidence: 0.98 },
  { pattern: /\b(?:bank\s+account(?:\s+(?:number|no\.?))?|account\s+number|routing\s+number|account\s+no\.?)\b\s*(?::|=|\bis\b)?\s*(\d(?:[ \t.-]?\d){5,33})(?!\d)/gi, category: "Bank account details", priority: 100, confidence: 0.96 },
  { pattern: /\b(?:api[_ -]?key|access[_ -]?token|auth(?:entication)?[_ -]?token|client[_ -]?secret|private[_ -]?key|bearer)\b\s*(?::|=|\bis\b)\s*([A-Za-z0-9/+=_.:-]{8,})/gi, category: "API key or token", priority: 100, confidence: 0.99 },
  { pattern: /\b(?:student\s+(?:id|number|roll)|roll\s+number|registration\s+(?:number|id)|employee\s+id|passport\s+(?:number|no\.?)|ssn|social\s+security\s+(?:number|no\.?))\b\s*(?::|=|\bis\b)\s*([A-Z0-9-]{4,24})/gi, category: "Personal identifier", priority: 95, confidence: 0.97 },
  { pattern: /\b(?:phone|mobile|telephone)\s+(?:number|no\.?)\b\s*(?::|=|\bis\b)?\s*(\+?[\d(). -]{7,25})/gi, category: "Phone number", priority: 95, confidence: 0.95 },
  { pattern: /\b(?:full\s+name|student\s+name|customer(?:\s+name)?|name)\b\s*(?::|=)\s*([A-Za-z][A-Za-z'’-]*(?:[ \t]+[A-Za-z][A-Za-z'’-]*){0,3})/gi, category: "Personal name", priority: 90, confidence: 0.92 },
  { pattern: /\b(?:home\s+address|mailing\s+address|street\s+address|address)\b\s*(?::|=)\s*([^\r\n,;]{8,120})/gi, category: "Home address", priority: 90, confidence: 0.94 },
  { pattern: /\b(?:date\s+of\s+birth|birthdate|dob)\b\s*(?::|=|\bis\b)\s*(\d{1,4}[/-]\d{1,2}[/-]\d{1,4})/gi, category: "Date of birth", priority: 95, confidence: 0.97 },
  { pattern: /\b(?:medical\s+record|health\s+record|diagnosis)\b\s*(?::|=)\s*([^\r\n,;]{3,100})/gi, category: "Health information", priority: 90, confidence: 0.93 },
  { pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, category: "Email address", priority: 85, confidence: 0.99 },
  { pattern: /(?<![\w])(?:\+\d{1,3}|00\d{1,3})[ \t().-]*\d(?:[ \t().-]*\d){6,14}(?!\w)/g, category: "Phone number", priority: 90, confidence: 0.96 },
  { pattern: /(?<!\w)(?:\+?1[ \t().-]?)?\(?[2-9]\d{2}\)?[ \t.-]?[2-9]\d{2}[ \t.-]?\d{4}(?!\w)/g, category: "Phone number", priority: 75, confidence: 0.9 },
  { pattern: /(?<!\w)[6-9]\d{4}[ \t.-]?\d{5}(?!\w)/g, category: "Phone number", priority: 75, confidence: 0.9 },
  { pattern: /(?<![\w])(?:\d[ \t.-]?){12,18}\d(?![\w])/g, category: "Payment card", priority: 85, confidence: 0.95 },
  { pattern: /\b[A-Z]{4}0[A-Z0-9]{6}\b/gi, category: "Banking code", priority: 90, confidence: 0.99 },
  { pattern: /\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{30,}|xox[baprs]-[A-Za-z0-9-]{16,})\b/g, category: "API key or token", priority: 85, confidence: 0.99 }
];

const VERHOEFF_MULTIPLICATION = [
  [0,1,2,3,4,5,6,7,8,9], [1,2,3,4,0,6,7,8,9,5], [2,3,4,0,1,7,8,9,5,6],
  [3,4,0,1,2,8,9,5,6,7], [4,0,1,2,3,9,5,6,7,8], [5,9,8,7,6,0,4,3,2,1],
  [6,5,9,8,7,1,0,4,3,2], [7,6,5,9,8,2,1,0,4,3], [8,7,6,5,9,3,2,1,0,4],
  [9,8,7,6,5,4,3,2,1,0]
];
const VERHOEFF_PERMUTATION = [
  [0,1,2,3,4,5,6,7,8,9], [1,5,7,6,2,8,3,0,9,4], [5,8,0,3,7,9,6,1,4,2],
  [8,9,1,6,0,4,3,5,2,7], [9,4,5,3,1,2,6,8,7,0], [4,2,8,6,5,7,3,9,0,1],
  [2,7,9,3,8,0,6,4,1,5], [7,0,4,6,9,1,3,2,5,8]
];

function passesLuhn(value) {
  const digits = value.replace(/\D/g, "").split("").map(Number);
  if (digits.length < 13 || digits.length > 19) return false;
  const checksum = digits.reduce((sum, digit, index) => {
    if (index % 2 !== digits.length % 2) return sum + digit;
    const doubled = digit * 2;
    return sum + (doubled > 9 ? doubled - 9 : doubled);
  }, 0);
  return checksum % 10 === 0;
}

function passesVerhoeff(value) {
  let checksum = 0;
  const digits = value.replace(/\D/g, "").split("").reverse().map(Number);
  digits.forEach((digit, index) => {
    checksum = VERHOEFF_MULTIPLICATION[checksum][VERHOEFF_PERMUTATION[(index + 1) % 8][digit]];
  });
  return checksum === 0;
}

function scanTextLocally(text, fieldName = "") {
  const candidates = [];

  FALLBACK_RULES.forEach((rule) => {
    rule.pattern.lastIndex = 0;
    let match;
    while ((match = rule.pattern.exec(text)) !== null) {
      const value = match[1] || match[0];
      const offset = match[1] ? match[0].indexOf(match[1]) : 0;
      const digits = value.replace(/\D/g, "").length;
      if (rule.category === "Payment card" && !passesLuhn(value)) continue;
      if (rule.category === "Phone number" && /^(?:\+|00)/.test(value) && (digits < 8 || digits > 15)) continue;
      if (rule.category === "Aadhaar number" && (value.replace(/\D/g, "")[0] === "0" || value.replace(/\D/g, "")[0] === "1" || !passesVerhoeff(value))) continue;
      candidates.push({
        start: match.index + offset,
        end: match.index + offset + value.length,
        category: rule.category,
        priority: rule.priority,
        confidence: rule.confidence
      });
      if (match[0].length === 0) rule.pattern.lastIndex++;
    }
  });

  const wordingRules = [
    [/\b(?:password|passwd|passcode|pin)\b/gi, "Authentication secret"],
    [/\b(?:credit\s+card|debit\s+card|card\s+(?:number|details|info)|cvv|cvc)\b/gi, "Payment card"],
    [/\b(?:bank\s+(?:account|details|information)|account\s+number|routing\s+number|iban)\b/gi, "Bank account details"],
    [/\b(?:phone|mobile|telephone)\s+(?:number|details)\b/gi, "Phone number"],
    [/\bemail\s+(?:address|details)\b/gi, "Email address"],
    [/\b(?:home\s+address|mailing\s+address|street\s+address)\b/gi, "Home address"],
    [/\b(?:student\s+(?:id|number|roll)|roll\s+number|registration\s+(?:number|id)|employee\s+id|passport\s+number|ssn|social\s+security\s+number)\b/gi, "Personal identifier"],
    [/\b(?:api[_ -]?key|access[_ -]?token|auth(?:entication)?[_ -]?token|client[_ -]?secret|private[_ -]?key|bearer\s+token)\b/gi, "API key or token"],
    [/\b(?:date\s+of\s+birth|birthdate|dob)\b/gi, "Date of birth"],
    [/\b(?:medical\s+record|health\s+record|diagnosis)\b/gi, "Health information"],
    [/\b(?:confidential|private\s+information|personal\s+information)\b/gi, "Confidential information"]
  ];

  wordingRules.forEach(([pattern, category]) => {
    let match;
    while ((match = pattern.exec(text)) !== null) {
      const lineStart = text.lastIndexOf("\n", match.index) + 1;
      const lineEndIndex = text.indexOf("\n", match.index + match[0].length);
      const lineEnd = lineEndIndex < 0 ? text.length : lineEndIndex;
      const valueFound = candidates.some((candidate) =>
        candidate.category === category && candidate.start >= lineStart &&
        candidate.end <= lineEnd && candidate.priority > 10
      );
      if (!valueFound) {
        candidates.push({
          start: match.index,
          end: match.index + match[0].length,
          category,
          priority: 10,
          confidence: 0.75
        });
      }
    }
  });

  const contextualCategories = {
    "phone number": "Phone number",
    "student id": "Personal identifier",
    "employee id": "Personal identifier",
    "payment card": "Payment card",
    "bank account": "Bank account details",
    "medical record": "Health information"
  };
  if (contextualCategories[fieldName] && candidates.length === 0 && text.trim()) {
    const start = text.length - text.trimStart().length;
    const end = text.trimEnd().length;
    candidates.push({
      start,
      end,
      category: contextualCategories[fieldName],
      priority: 70,
      confidence: 0.75
    });
  }

  const selected = [];
  candidates.sort((a, b) => b.priority - a.priority || a.start - b.start || (b.end - b.start) - (a.end - a.start));
  candidates.forEach((candidate) => {
    if (!selected.some((existing) => candidate.start < existing.end && candidate.end > existing.start)) {
      selected.push(candidate);
    }
  });
  selected.sort((a, b) => a.start - b.start);

  const findings = [];
  const segments = [];
  let cursor = 0;
  selected.forEach((item) => {
    if (cursor < item.start) segments.push({ kind: "text", text: text.slice(cursor, item.start) });
    const severity = item.priority >= 85 ? "high" : "medium";
    segments.push({
      kind: "finding",
      text: text.slice(item.start, item.end),
      finding: { category: item.category, severity, confidence: item.confidence }
    });
    findings.push({
      rule_id: item.category.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""),
      category: item.category,
      severity,
      confidence: item.confidence,
      action: "Remove or protect before sharing."
    });
    cursor = item.end;
  });
  if (cursor < text.length) segments.push({ kind: "text", text: text.slice(cursor) });

  return {
    state: findings.length ? "review_required" : "no_matches_unverified",
    message: findings.length
      ? "Sensitive information detected. Protect it before sharing."
      : "No configured sensitive patterns matched.",
    findings,
    preview_segments: segments
  };
}

function showLocalScanResult(result, { announce = false, recordActivity = false, reason } = {}) {
  lastScannedText = null;
  scanRecordId = null;
  if (sourceText) {
    sourceText.value = (result.preview_segments || [])
      .map((segment) => segment.kind === "finding" ? "[REDACTED]" : segment.text)
      .join("");
  }
  updateSendButton();
  currentDetectionCount = result.findings.length;
  updateDashboard();
  renderProtectedPreview(result.preview_segments);
  renderFindingSummary(result.findings, result.state);

  const reasonText = reason
    ? ` ${reason}`
    : " Start server.py and open http://127.0.0.1:8000 for secure transmission.";
  if (result.findings.length) {
    setStatus(
      scanStatus,
      `${result.findings.length} sensitive item(s) detected. Encryption requires the local scanner backend.${reasonText}`,
      "warning"
    );
    if (announce) {
      const categories = [...new Set(result.findings.map((finding) => finding.category))].join(", ");
      showSensitivePopup(`${result.findings.length} potential finding(s): ${categories}. Browser-only scan; local encryption is unavailable.`);
      playDetectionWarning();
    }
  } else {
    setStatus(
      scanStatus,
      `No configured patterns matched in browser fallback. Local encryption is unavailable.${reasonText}`,
      "warning"
    );
  }
  setStatus(sendStatus, "Not encrypted. Start the local scanner backend and scan again.", "danger");

  if (recordActivity) {
    addActivity(
      "Text scan",
      "Browser fallback",
      `${result.findings.length} finding(s); secure sending disabled; values not logged`
    );
  }
}

async function postDlp(path, payload) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    cache: "no-store",
    credentials: "same-origin",
    body: JSON.stringify(payload)
  });
  const result = await response.json();
  if (!result || typeof result !== "object") {
    throw new Error("Scanner returned an invalid response.");
  }
  if (!response.ok) {
    throw new Error(result.message || "Scanner unavailable.");
  }
  return result;
}

function updateSendButton() {
  if (!sendSecurelyButton) return;
  const hasText = Boolean(sourceText?.value.trim());
  const hasImage = Boolean(imageUpload?.files?.length);
  sendSecurelyButton.disabled =
    sending
    || (!hasText && !hasImage);
}

function updateScanResult(result, { announce = false, recordActivity = false } = {}) {
  const findings = Array.isArray(result.findings) ? result.findings : [];
  if (
    result.encrypted_storage !== true
    || typeof result.record_id !== "string"
    || typeof result.safe_content !== "string"
  ) {
    throw new Error("Scanner backend does not support encrypted staging. Nothing was sent.");
  }
  if (result.source_kind === "image" && typeof result.extracted_text !== "string") {
    throw new Error("Local OCR did not return extracted text. Nothing was sent.");
  }
  scanRecordId = result.record_id;
  const displayedText = result.source_kind === "image"
    ? result.extracted_text
    : result.safe_content;
  lastScannedText = displayedText;
  if (sourceText) sourceText.value = displayedText;
  if (imageUpload) imageUpload.value = "";
  updateSendButton();
  currentDetectionCount = findings.length;
  updateDashboard();
  renderProtectedPreview(result.preview_segments);
  renderFindingSummary(findings, result.state);

  if (result.state === "no_matches_unverified") {
    setStatus(scanStatus, "No configured patterns matched. Scanning cannot guarantee that all private information was found.", "warning");
  } else {
    const statusClass = result.state === "blocked" ? "danger" : "warning";
    setStatus(scanStatus, `${findings.length} sensitive item(s) detected. Review the masked preview; the original is encrypted locally.`, statusClass);
  }
  setStatus(
    sendStatus,
    `Original encrypted in the local vault as ${scanRecordId}. Nothing has been sent off this device.`,
    "success"
  );

  if (findings.length > 0) {
    const categories = [...new Set(findings.map((finding) => finding.category))].join(", ");
    if (announce) {
      showSensitivePopup(`${findings.length} potential finding(s): ${categories}. Values are masked in the protected preview.`);
      playDetectionWarning();
    }
    if (recordActivity) {
      const sourceKind = result.source_kind === "image" ? "Image OCR" : "Text scan";
      addActivity(sourceKind, result.state === "blocked" ? "Blocked" : "Review required", `${findings.length} finding(s); matched values not logged`);
    }
  } else {
    if (recordActivity) {
      const sourceKind = result.source_kind === "image" ? "Image OCR" : "Text scan";
      addActivity(sourceKind, "No matches", "No configured patterns matched; review before sharing");
    }
  }
}

async function scanText({ announce = false, recordActivity = false } = {}) {
  if (!sourceText) return false;
  const content = sourceText.value;
  const currentGeneration = ++scanGeneration;
  lastScannedText = null;
  scanRecordId = null;
  updateSendButton();

  if (!content.trim()) {
    currentDetectionCount = 0;
    updateDashboard();
    renderProtectedPreview([]);
    renderFindingSummary([], "empty");
    setStatus(scanStatus, "Enter information to scan.", "warning");
    setStatus(sendStatus, "Scan information to encrypt it locally.", "warning");
    return false;
  }

  if (content.length > MAX_TEXT_CHARS) {
    currentDetectionCount = 0;
    updateDashboard();
    renderProtectedPreview([]);
    renderFindingSummary([], "empty");
    setStatus(scanStatus, "Input exceeds the local scanner limit. Nothing was submitted.", "danger");
    setStatus(sendStatus, "Not encrypted. Shorten the text and scan it again.", "danger");
    return false;
  }

  setStatus(scanStatus, "Scanning locally…", "warning");
  scanStatus?.classList.add("is-scanning");
  try {
    const result = await postDlp("/api/scan", {
      text: content,
      field_name: scanContext?.value || ""
    });
    if (currentGeneration !== scanGeneration) return false;
    updateScanResult(result, { announce, recordActivity });
    return Boolean(scanRecordId && lastScannedText === sourceText.value);
  } catch {
    if (currentGeneration !== scanGeneration) return false;
    lastScannedText = null;
    scanRecordId = null;
    updateSendButton();
    currentDetectionCount = 0;
    updateDashboard();
    const localServerHint = API_BASE_URL
      ? " Start server.py and open http://127.0.0.1:8000; if Brave blocks localhost access, allow it for this page."
      : " Start or restart server.py and open this site through http://127.0.0.1:8000.";
    const result = scanTextLocally(content, scanContext?.value || "");
    showLocalScanResult(result, {
      announce,
      recordActivity,
      reason: `The backend is unavailable.${localServerHint}`
    });
    return false;
  }
}

function bytesToBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

async function scanImage() {
  const file = imageUpload?.files?.[0];
  if (!file) {
    setStatus(scanStatus, "Choose an image before scanning.", "warning");
    return false;
  }
  if (sourceText?.value.trim()) {
    setStatus(scanStatus, "Clear the text field before scanning an image.", "warning");
    return false;
  }
  if (file.size > 5_000_000) {
    setStatus(scanStatus, "Image exceeds the 5 MB limit. Nothing was uploaded.", "danger");
    return false;
  }

  const currentGeneration = ++scanGeneration;
  lastScannedText = null;
  scanRecordId = null;
  updateSendButton();
  setStatus(scanStatus, "Processing image with the loopback-only backend for local OCR…", "warning");
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const result = await postDlp("/api/scan-image", {
      image: bytesToBase64(bytes),
      field_name: scanContext?.value || ""
    });
    if (currentGeneration !== scanGeneration) return false;
    updateScanResult(result, { announce: true, recordActivity: true });
    return Boolean(scanRecordId && lastScannedText === sourceText?.value);
  } catch (error) {
    if (currentGeneration !== scanGeneration) return false;
    scanRecordId = null;
    lastScannedText = null;
    updateSendButton();
    setStatus(scanStatus, error.message || "Local OCR or encrypted storage failed. The image was not sent.", "danger");
    setStatus(sendStatus, "Not encrypted. Scan the image successfully first.", "danger");
    return false;
  }
}

// ---------- SAFE SAMPLE AND FORM ACTIONS ----------

function loadSample() {
  if (!sourceText) return;

  sourceText.value =
    "Customer: Example User\n" +
    "Email: alex@example.com\n" +
    "Password: SamplePass123!\n" +
    "Card number: 4111 1111 1111 1111\n" +
    "Bank account: 1234567890";
  if (textFindStatus) textFindStatus.textContent = "";
  if (imageUpload) imageUpload.value = "";
  scanRecordId = null;
  lastScannedText = null;
  updateSendButton();
  setStatus(scanStatus, "Fictional sample loaded. Click Scan Information to check it.", "warning");
  setStatus(sendStatus, "Scan information to encrypt it locally.", "warning");
}

function clearForm() {
  scanGeneration++;
  if (sourceText) sourceText.value = "";
  if (imageUpload) imageUpload.value = "";
  if (scanContext) scanContext.value = "";
  if (textFindInput) textFindInput.value = "";
  if (textFindStatus) textFindStatus.textContent = "";

  scanRecordId = null;
  lastScannedText = null;
  updateSendButton();
  currentDetectionCount = 0;
  updateDashboard();
  renderProtectedPreview([]);
  renderFindingSummary([], "empty");
  if (sanitizedOutput) sanitizedOutput.textContent = "Your protected result will appear here.";
  setStatus(scanStatus, "Text cleared. Add information to start a new scan.");
  setStatus(sendStatus, "Scan information to encrypt it locally.");
}

async function sendSecurely() {
  sending = true;
  updateSendButton();
  setStatus(sendStatus, "Scanning and verifying AES-256-GCM encrypted local storage…", "warning");
  try {
    let prepared = Boolean(
      scanRecordId
      && lastScannedText !== null
      && lastScannedText === sourceText?.value
    );
    if (!prepared) {
      if (sourceText?.value.trim()) {
        prepared = await scanText({ announce: true, recordActivity: true });
      } else if (imageUpload?.files?.length) {
        prepared = await scanImage();
      }
    }
    if (
      !prepared
      || !scanRecordId
      || lastScannedText === null
      || lastScannedText !== sourceText?.value
    ) {
      throw new Error("Not completed. Scan and verify encrypted local storage before continuing.");
    }

    setStatus(sendStatus, "Verifying encrypted record on this device…", "warning");
    const result = await postDlp("/api/local-seal", {
      record_id: scanRecordId
    });
    if (result.success !== true || result.encrypted_storage !== true || result.mode !== "local-encrypted") {
      throw new Error(result.message || "Encrypted local storage could not be verified.");
    }

    const count = Number.isInteger(result.finding_count) ? result.finding_count : 0;
    setStatus(sendStatus, `Encrypted and verified locally with AES-256-GCM. Nothing was sent off this device. ${count} sensitive category/categories protected.`, "success");
    addActivity("Local encryption", "Verified", `${count} sensitive category/categories; original remains encrypted; nothing transmitted`);
  } catch (error) {
    setStatus(sendStatus, error.message || "Local encryption could not be verified.", "danger");
    addActivity("Local encryption", "Failed", "Encrypted storage could not be verified; original text not logged");
  } finally {
    sending = false;
    updateSendButton();
  }
}

function findInSourceText() {
  const query = textFindInput?.value.trim();
  const text = sourceText?.value || "";
  if (!query) {
    if (textFindStatus) textFindStatus.textContent = "Enter a word or phrase to find.";
    return;
  }
  if (!text) {
    if (textFindStatus) textFindStatus.textContent = "There is no text to search.";
    return;
  }

  const startAt = sourceText.selectionEnd > 0 ? sourceText.selectionEnd : 0;
  const matchAt = text.toLocaleLowerCase().indexOf(query.toLocaleLowerCase(), startAt);
  const wrappedMatchAt = matchAt === -1
    ? text.toLocaleLowerCase().indexOf(query.toLocaleLowerCase())
    : matchAt;
  if (wrappedMatchAt === -1) {
    if (textFindStatus) textFindStatus.textContent = "No match found in this text.";
    return;
  }

  sourceText.focus();
  sourceText.setSelectionRange(wrappedMatchAt, wrappedMatchAt + query.length);
  if (textFindStatus) {
    textFindStatus.textContent = matchAt === -1
      ? "Match found (wrapped to the beginning). Search stayed on this device."
      : "Match found. Search stayed on this device.";
  }
}

if (scanForm) {
  scanForm.addEventListener("submit", (event) => {
    event.preventDefault();
    void scanText({ announce: true, recordActivity: true });
  });
}

if (sourceText) {
  sourceText.addEventListener("input", () => {
    lastScannedText = null;
    scanRecordId = null;
    if (textFindStatus) textFindStatus.textContent = "";
    updateSendButton();
    setStatus(sendStatus, "Text changed. Scan again to encrypt it locally.", "warning");
  });
}

if (scanContext) scanContext.addEventListener("change", () => {
  lastScannedText = null;
  scanRecordId = null;
  updateSendButton();
  setStatus(sendStatus, "Scan again with the selected field type to encrypt it locally.", "warning");
});

if (imageUpload) imageUpload.addEventListener("change", () => {
  lastScannedText = null;
  scanRecordId = null;
  if (textFindStatus) textFindStatus.textContent = "";
  updateSendButton();
  setStatus(scanStatus, "Image selected. Click Scan Image to run local OCR.", "warning");
});

if (loadSampleButton) loadSampleButton.addEventListener("click", loadSample);
if (clearFormButton) clearFormButton.addEventListener("click", clearForm);
if (scanImageButton) scanImageButton.addEventListener("click", () => void scanImage());
if (findInTextButton) findInTextButton.addEventListener("click", findInSourceText);
if (textFindInput) {
  textFindInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      findInSourceText();
    }
  });
}
if (sendSecurelyButton) sendSecurelyButton.addEventListener("click", () => void sendSecurely());

if (clearLogButton) {
  clearLogButton.addEventListener("click", () => {
    activity = [];
    renderActivity();
  });
}

// ---------- INITIALIZE ----------

renderActivity();
updateDashboard();

setStatus(
  scanStatus,
  "Ready. Enter information to scan and protect."
);
setStatus(sendStatus, "Scan information to encrypt it locally.", "warning");
updateSendButton();

console.log("PrivacyLens demo initialized.");

// ---------- SCROLLING CYBER BACKGROUND ----------

const cyberCanvas = document.getElementById("cyber-background");

if (cyberCanvas) {
  const context = cyberCanvas.getContext("2d", { alpha: true });

  if (!context) {
    document.body.classList.add("cyber-background-fallback");
  } else {
    const motionPreference = window.matchMedia("(prefers-reduced-motion: reduce)");
    const random = (min, max) => min + Math.random() * (max - min);
    const randomHex = (length = 8) =>
      Array.from({ length }, () => Math.floor(Math.random() * 16).toString(16)).join("").toUpperCase();
    const codeWords = ["AUTH", "TRACE", "FIREWALL", "NODE", "ACCESS", "KERNEL", "ENCRYPT", "SYS", "NULL", "ROOT"];
    let width = 0;
    let height = 0;
    let pixelRatio = 1;
    let tileWidth = 0;
    let circuitRows = [];
    let codeStrips = [];
    let hexColumns = [];
    let targetScroll = 0;
    let scrollOffset = 0;
    let animationFrame = 0;
    let lastFrameTime = 0;
    let reducedMotion = motionPreference.matches;

    function makeCircuitRows() {
      tileWidth = width + 520;
      circuitRows = [];

      const rowCount = Math.ceil(height / 112) + 4;
      for (let rowIndex = 0; rowIndex < rowCount; rowIndex++) {
        const baseY = rowIndex * 112 - 224;
        let currentY = baseY;
        let currentX = 0;
        const points = [{ x: currentX, y: currentY }];

        while (currentX < tileWidth) {
          currentX = Math.min(tileWidth, currentX + random(78, 164));
          if (currentX >= tileWidth) {
            points.push({ x: currentX, y: currentY });
            if (currentY !== baseY) points.push({ x: currentX, y: baseY });
            points.push({ x: tileWidth, y: baseY });
            break;
          }

          points.push({ x: currentX, y: currentY });

          if (Math.random() > 0.42) {
            const branchY = Math.max(baseY - 43, Math.min(baseY + 43, currentY + (Math.random() > 0.5 ? 38 : -38)));
            points.push({ x: currentX, y: branchY });
            currentY = branchY;
          }
        }

        const segments = [];
        let totalLength = 0;
        for (let index = 1; index < points.length; index++) {
          const from = points[index - 1];
          const to = points[index];
          const length = Math.hypot(to.x - from.x, to.y - from.y);
          segments.push({ from, to, start: totalLength, length });
          totalLength += length;
        }

        circuitRows.push({ points, segments, totalLength, phase: rowIndex * 47, rowIndex });
      }
    }

    function makeTextLayers() {
      codeStrips = [];
      hexColumns = [];
      const stripCount = Math.ceil(height / 58) + 4;

      for (let index = 0; index < stripCount; index++) {
        const tokens = Array.from({ length: Math.ceil(tileWidth / 85) + 4 }, () =>
          `${codeWords[Math.floor(Math.random() * codeWords.length)]}_${randomHex(4)}`
        );
        codeStrips.push({
          y: index * 58 - 174,
          text: tokens.join("  //  "),
          phase: random(0, 2200),
          speed: random(5, 15),
          alpha: random(0.13, 0.28)
        });
      }

      const columnCount = Math.ceil(width / 94) + 2;
      for (let index = 0; index < columnCount; index++) {
        hexColumns.push({
          x: index * 94 + random(-14, 14),
          phase: random(0, 2200),
          speed: random(8, 22),
          chars: Array.from({ length: 40 }, () => randomHex(2)),
          tags: Array.from({ length: 5 }, () => randomHex(4))
        });
      }
    }

    function resizeCanvas() {
      const bounds = cyberCanvas.getBoundingClientRect();
      width = Math.max(1, bounds.width || window.innerWidth);
      height = Math.max(1, bounds.height || window.innerHeight);
      pixelRatio = Math.min(window.devicePixelRatio || 1, 2);
      cyberCanvas.width = Math.round(width * pixelRatio);
      cyberCanvas.height = Math.round(height * pixelRatio);
      context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
      makeCircuitRows();
      makeTextLayers();
      drawFrame(performance.now(), true);
    }

    function pointOnPath(segments, distance) {
      for (const segment of segments) {
        if (distance <= segment.start + segment.length) {
          const progress = segment.length ? (distance - segment.start) / segment.length : 0;
          return {
            x: segment.from.x + (segment.to.x - segment.from.x) * progress,
            y: segment.from.y + (segment.to.y - segment.from.y) * progress,
            angle: Math.atan2(segment.to.y - segment.from.y, segment.to.x - segment.from.x)
          };
        }
      }
      return segments[segments.length - 1].to;
    }

    function drawCircuitLayer(time, parallax) {
      const horizontalTravel = reducedMotion ? 0 : (time * 0.012) % tileWidth;

      for (const route of circuitRows) {
        for (let copy = -1; copy <= 1; copy++) {
          const shiftX = copy * tileWidth - horizontalTravel;
          const shiftY = Math.sin(time * 0.00015 + route.phase) * 2 - parallax * 0.16;
          context.beginPath();
          route.points.forEach((point, index) => {
            const x = point.x + shiftX;
            const y = point.y + shiftY;
            if (index === 0) context.moveTo(x, y);
            else context.lineTo(x, y);
          });
          context.strokeStyle = "rgba(159, 24, 43, 0.34)";
          context.lineWidth = route.rowIndex % 3 === 0 ? 1.15 : 0.8;
          context.shadowColor = "rgba(198, 29, 51, 0.25)";
          context.shadowBlur = 5;
          context.stroke();
          context.shadowBlur = 0;

          const pulseDistance = reducedMotion
            ? route.totalLength * 0.5
            : (time * 0.028 + route.phase * 3) % route.totalLength;
          const pulse = pointOnPath(route.segments, pulseDistance);
          const pulseFade = reducedMotion ? 0.5 : 0.5 + Math.sin(time * 0.0012 + route.phase) * 0.22;
          context.save();
          context.translate(pulse.x + shiftX, pulse.y + shiftY);
          context.rotate(pulse.angle);
          context.beginPath();
          context.moveTo(-6, 0);
          context.lineTo(6, 0);
          context.fillStyle = `rgba(255, 91, 108, ${pulseFade})`;
          context.strokeStyle = `rgba(255, 91, 108, ${pulseFade})`;
          context.lineWidth = 2;
          context.shadowColor = "rgba(255, 31, 57, 0.9)";
          context.shadowBlur = 12;
          context.stroke();
          context.shadowBlur = 0;
          context.restore();

          route.points.forEach((point, index) => {
            if (index === 0 || index === route.points.length - 1 || index % 2 === 0) {
              const glow = reducedMotion
                ? 0.42
                : 0.28 + (Math.sin(time * 0.001 + route.phase + index) + 1) * 0.14;
              context.beginPath();
              context.arc(point.x + shiftX, point.y + shiftY, 1.35, 0, Math.PI * 2);
              context.fillStyle = `rgba(238, 70, 88, ${glow})`;
              context.shadowColor = "rgba(226, 28, 52, 0.62)";
              context.shadowBlur = 7;
              context.fill();
              context.shadowBlur = 0;
            }
          });
        }
      }
    }

    function drawTextLayers(time, parallax) {
      const stripWidth = width + 520;
      context.font = "10px Consolas, 'Courier New', monospace";
      context.textBaseline = "middle";

      for (const strip of codeStrips) {
        const offset = reducedMotion ? 0 : (time * strip.speed * 0.001 + strip.phase) % stripWidth;
        context.fillStyle = `rgba(191, 107, 118, ${strip.alpha})`;
        const y = strip.y - parallax * 0.3;
        for (let copy = -1; copy <= 1; copy++) {
          context.fillText(strip.text, copy * stripWidth - offset, y);
        }
      }

      context.font = "9px Consolas, 'Courier New', monospace";
      for (const column of hexColumns) {
        const streamHeight = 40 * 19;
        const offset = reducedMotion ? 0 : (time * column.speed * 0.001 + column.phase) % streamHeight;
        context.fillStyle = "rgba(207, 87, 101, 0.2)";
        for (let cycle = -1; cycle <= 2; cycle++) {
          for (let index = 0; index < column.chars.length; index++) {
            const y = index * 19 - offset + cycle * streamHeight - 130 - parallax * 0.48;
            context.fillText(column.chars[index], column.x, y);
            if (index % 9 === 0) {
              context.fillStyle = "rgba(225, 180, 184, 0.3)";
              context.fillText(`0x${column.tags[Math.floor(index / 9) % column.tags.length]}`, column.x + 14, y);
              context.fillStyle = "rgba(207, 87, 101, 0.2)";
            }
          }
        }
      }
    }

    function drawDiagnostics(time, parallax) {
      context.font = "9px Consolas, 'Courier New', monospace";
      context.fillStyle = "rgba(226, 190, 194, 0.36)";
      const diagnostics = ["SYS://AUTH_GATE", "TRACE_ID", "0x7F3A", "MEM_LOCK", "ACCESS::LOCAL"];
      diagnostics.forEach((label, index) => {
        const x = width * 0.08 + index * 176 + (reducedMotion ? 0 : (time * 0.006) % 176);
        const y = height * (0.18 + (index % 4) * 0.2) - parallax * (0.18 + index * 0.04);
        context.fillText(label, x % (width + 176) - 60, y);
      });

      const scanY = reducedMotion ? height * 0.52 : (time * 0.018) % (height + 120) - 60;
      const scanGradient = context.createLinearGradient(0, scanY - 9, 0, scanY + 9);
      scanGradient.addColorStop(0, "rgba(207, 24, 48, 0)");
      scanGradient.addColorStop(0.5, "rgba(207, 24, 48, 0.075)");
      scanGradient.addColorStop(1, "rgba(207, 24, 48, 0)");
      context.fillStyle = scanGradient;
      context.fillRect(0, scanY - 9, width, 18);
    }

    function drawFrame(time, force = false) {
      if (!force && document.hidden) return;
      context.clearRect(0, 0, width, height);

      const background = context.createLinearGradient(0, 0, width, height);
      background.addColorStop(0, "rgba(7, 5, 7, 0.24)");
      background.addColorStop(0.55, "rgba(14, 6, 9, 0.1)");
      background.addColorStop(1, "rgba(3, 3, 5, 0.3)");
      context.fillStyle = background;
      context.fillRect(0, 0, width, height);

      scrollOffset += (targetScroll - scrollOffset) * 0.045;
      drawCircuitLayer(time, scrollOffset * height);
      drawTextLayers(time, scrollOffset * height);
      drawDiagnostics(time, scrollOffset * height);
    }

    function animate(time) {
      if (reducedMotion || document.hidden) {
        animationFrame = 0;
        return;
      }

      if (time - lastFrameTime >= 1000 / 50) {
        lastFrameTime = time;
        drawFrame(time);
      }
      animationFrame = window.requestAnimationFrame(animate);
    }

    function startAnimation() {
      if (animationFrame) window.cancelAnimationFrame(animationFrame);
      drawFrame(performance.now(), true);
      if (!reducedMotion && !document.hidden) {
        animationFrame = window.requestAnimationFrame(animate);
      }
    }

    function updateScroll() {
      const scrollableHeight = document.documentElement.scrollHeight - window.innerHeight;
      targetScroll = reducedMotion || scrollableHeight <= 0 ? 0 : window.scrollY / scrollableHeight;
      if (reducedMotion) drawFrame(performance.now(), true);
    }

    resizeCanvas();
    startAnimation();
    window.addEventListener("resize", resizeCanvas, { passive: true });
    window.visualViewport?.addEventListener("resize", resizeCanvas, { passive: true });
    window.addEventListener("scroll", updateScroll, { passive: true });
    document.addEventListener("visibilitychange", startAnimation);
    motionPreference.addEventListener("change", (event) => {
      reducedMotion = event.matches;
      startAnimation();
    });
  }
}

if (false) {
  import("https://cdn.jsdelivr.net/npm/three@0.180.0/build/three.module.js")
    .then((THREE) => {
      const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      const renderer = new THREE.WebGLRenderer({
        canvas: cyberCanvas,
        alpha: true,
        antialias: false
      });
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
      renderer.setClearColor(0x000000, 0);

      const scene = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 100);
      const network = new THREE.Group();
      const security = new THREE.Group();

      camera.position.set(0, 0, 30);
      camera.lookAt(0, 0, 0);
      scene.add(network);

      const board = new THREE.Mesh(
        new THREE.PlaneGeometry(58, 38),
        new THREE.MeshBasicMaterial({ color: 0x030a18, transparent: true, opacity: 0.42 })
      );
      board.position.z = -3;
      network.add(board);

      const boardLines = [];
      for (let x = -27; x <= 27; x += 2.4) {
        boardLines.push(x, -18, -2.8, x, 18, -2.8);
      }
      for (let y = -18; y <= 18; y += 2.4) {
        boardLines.push(-29, y, -2.8, 29, y, -2.8);
      }
      const boardGridGeometry = new THREE.BufferGeometry();
      boardGridGeometry.setAttribute("position", new THREE.Float32BufferAttribute(boardLines, 3));
      network.add(new THREE.LineSegments(
        boardGridGeometry,
        new THREE.LineBasicMaterial({ color: 0x12345a, transparent: true, opacity: 0.18 })
      ));

      const shieldShape = new THREE.Shape();
      shieldShape.moveTo(0, 4.6);
      shieldShape.bezierCurveTo(1.45, 3.75, 2.55, 3.45, 3.1, 3.2);
      shieldShape.lineTo(2.72, 0.35);
      shieldShape.quadraticCurveTo(2.25, -2.5, 0, -4.35);
      shieldShape.quadraticCurveTo(-2.25, -2.5, -2.72, 0.35);
      shieldShape.lineTo(-3.1, 3.2);
      shieldShape.bezierCurveTo(-2.55, 3.45, -1.45, 3.75, 0, 4.6);

      const shieldGeometry = new THREE.ExtrudeGeometry(shieldShape, {
        depth: 0.3,
        bevelEnabled: true,
        bevelSegments: 3,
        steps: 1,
        bevelSize: 0.1,
        bevelThickness: 0.12
      });
      security.add(new THREE.Mesh(
        shieldGeometry,
        new THREE.MeshBasicMaterial({
          color: 0x0b2241,
          transparent: true,
          opacity: 0.84,
          side: THREE.DoubleSide,
          depthWrite: false
        })
      ));
      security.add(new THREE.LineSegments(
        new THREE.EdgesGeometry(shieldGeometry),
        new THREE.LineBasicMaterial({ color: 0x29d9ff, transparent: true, opacity: 0.92 })
      ));

      const dataCanvas = document.createElement("canvas");
      dataCanvas.width = 512;
      dataCanvas.height = 512;
      const dataContext = dataCanvas.getContext("2d");
      dataContext.fillStyle = "#07172c";
      dataContext.fillRect(0, 0, 512, 512);
      dataContext.font = "19px Consolas, monospace";
      dataContext.fillStyle = "rgba(65, 188, 247, 0.55)";
      for (let row = 0; row < 17; row++) {
        let bits = "";
        for (let column = 0; column < 20; column++) {
          bits += (row * 7 + column * 3) % 2 ? "1 " : "0 ";
        }
        dataContext.fillText(bits, 53, 48 + row * 25);
      }
      dataContext.fillStyle = "#d8fbff";
      dataContext.font = "bold 18px Consolas, monospace";
      dataContext.fillText("IDENTITY FIREWALL", 145, 445);

      const shieldTexture = new THREE.CanvasTexture(dataCanvas);
      shieldTexture.colorSpace = THREE.SRGBColorSpace;
      const shieldFace = new THREE.Mesh(
        new THREE.ShapeGeometry(shieldShape),
        new THREE.MeshBasicMaterial({
          map: shieldTexture,
          color: 0xb5f2ff,
          transparent: true,
          opacity: 0.58,
          side: THREE.DoubleSide,
          depthWrite: false
        })
      );
      shieldFace.position.z = 0.34;
      security.add(shieldFace);

      const lockShape = new THREE.Shape();
      lockShape.moveTo(-0.88, -1.28);
      lockShape.lineTo(0.88, -1.28);
      lockShape.quadraticCurveTo(1.08, -1.28, 1.08, -1.08);
      lockShape.lineTo(1.08, 0.05);
      lockShape.quadraticCurveTo(1.08, 0.25, 0.88, 0.25);
      lockShape.lineTo(-0.88, 0.25);
      lockShape.quadraticCurveTo(-1.08, 0.25, -1.08, 0.05);
      lockShape.lineTo(-1.08, -1.08);
      lockShape.quadraticCurveTo(-1.08, -1.28, -0.88, -1.28);
      const lockGeometry = new THREE.ShapeGeometry(lockShape);
      const lockMesh = new THREE.Mesh(
        lockGeometry,
        new THREE.MeshBasicMaterial({ color: 0x07172c, transparent: true, opacity: 0.96, side: THREE.DoubleSide })
      );
      lockMesh.position.set(0, -0.5, 0.42);
      security.add(lockMesh);

      const lockOutline = new THREE.LineSegments(
        new THREE.EdgesGeometry(lockGeometry),
        new THREE.LineBasicMaterial({ color: 0x9ceeff, transparent: true, opacity: 0.96 })
      );
      lockOutline.position.set(0, -0.5, 0.46);
      security.add(lockOutline);

      const shackleCurve = new THREE.EllipseCurve(0, 0.12, 0.66, 0.78, Math.PI, 0, false, 0);
      const shackleGeometry = new THREE.BufferGeometry().setFromPoints(shackleCurve.getPoints(32));
      const shackle = new THREE.Line(
        shackleGeometry,
        new THREE.LineBasicMaterial({ color: 0x9ceeff, transparent: true, opacity: 0.96 })
      );
      shackle.position.set(0, 0.42, 0.47);
      security.add(shackle);

      const keyhole = new THREE.Group();
      const keyholeDot = new THREE.Mesh(
        new THREE.CircleGeometry(0.18, 20),
        new THREE.MeshBasicMaterial({ color: 0x9ceeff })
      );
      keyholeDot.position.set(0, -0.12, 0.52);
      keyhole.add(keyholeDot);
      const keyholeTail = new THREE.Mesh(
        new THREE.PlaneGeometry(0.14, 0.43),
        new THREE.MeshBasicMaterial({ color: 0x9ceeff })
      );
      keyholeTail.position.set(0, -0.42, 0.52);
      keyhole.add(keyholeTail);
      security.add(keyhole);

      const tracePaths = [
        [[-3.1, 3.1], [-5.4, 3.1], [-7.2, 4.9], [-18, 4.9]],
        [[-3.1, 2], [-10, 2], [-12, 4], [-21, 4]],
        [[-3.1, 0.7], [-8, 0.7], [-10, -1.3], [-19, -1.3]],
        [[-2.8, -2], [-6.6, -2], [-8.7, -4.1], [-17, -4.1]],
        [[-2.2, -3.2], [-4.3, -3.2], [-6.1, -5], [-20, -5]],
        [[3.1, 3.1], [5.4, 3.1], [7.2, 4.9], [18, 4.9]],
        [[3.1, 2], [10, 2], [12, 4], [21, 4]],
        [[3.1, 0.7], [8, 0.7], [10, -1.3], [19, -1.3]],
        [[2.8, -2], [6.6, -2], [8.7, -4.1], [17, -4.1]],
        [[2.2, -3.2], [4.3, -3.2], [6.1, -5], [20, -5]],
        [[-1.6, 4.2], [-1.6, 7.4], [-3.6, 9.4], [-15, 9.4]],
        [[1.6, 4.2], [1.6, 7.4], [3.6, 9.4], [16, 9.4]],
        [[-1.6, -4], [-1.6, -7.1], [-3.6, -9.1], [-14, -9.1]],
        [[1.6, -4], [1.6, -7.1], [3.6, -9.1], [15, -9.1]]
      ];
      const tracePositions = [];
      const traceNodes = [];
      tracePaths.forEach((path) => {
        for (let index = 0; index < path.length - 1; index++) {
          tracePositions.push(
            path[index][0], path[index][1], 0.08,
            path[index + 1][0], path[index + 1][1], 0.08
          );
        }
        const [nodeX, nodeY] = path[path.length - 1];
        traceNodes.push(nodeX, nodeY, 0.12);
      });

      const traceGeometry = new THREE.BufferGeometry();
      traceGeometry.setAttribute("position", new THREE.Float32BufferAttribute(tracePositions, 3));
      security.add(new THREE.LineSegments(
        traceGeometry,
        new THREE.LineBasicMaterial({ color: 0x18b6ff, transparent: true, opacity: 0.72 })
      ));

      const traceNodeGeometry = new THREE.BufferGeometry();
      traceNodeGeometry.setAttribute("position", new THREE.Float32BufferAttribute(traceNodes, 3));
      security.add(new THREE.Points(
        traceNodeGeometry,
        new THREE.PointsMaterial({ color: 0x84e8ff, size: 0.16, transparent: true, opacity: 0.92 })
      ));

      const pinPositions = [];
      for (let index = 0; index < 11; index++) {
        const pin = -2.7 + index * 0.54;
        pinPositions.push(pin, 4.65, 0.18, pin, 5.35, 0.18);
        pinPositions.push(pin, -4.65, 0.18, pin, -5.35, 0.18);
        pinPositions.push(4.65, pin, 0.18, 5.35, pin, 0.18);
        pinPositions.push(-4.65, pin, 0.18, -5.35, pin, 0.18);
      }
      const pinGeometry = new THREE.BufferGeometry();
      pinGeometry.setAttribute("position", new THREE.Float32BufferAttribute(pinPositions, 3));
      security.add(new THREE.LineSegments(
        pinGeometry,
        new THREE.LineBasicMaterial({ color: 0xd59b55, transparent: true, opacity: 0.9 })
      ));

      const orbit = new THREE.Mesh(
        new THREE.TorusGeometry(5.8, 0.025, 5, 120),
        new THREE.MeshBasicMaterial({ color: 0x2cc9ff, transparent: true, opacity: 0.36 })
      );
      orbit.scale.y = 0.8;
      orbit.position.z = -0.3;
      security.add(orbit);

      const scanBeam = new THREE.Line(
        new THREE.BufferGeometry().setFromPoints([
          new THREE.Vector3(-2.4, 0, 0.52),
          new THREE.Vector3(2.4, 0, 0.52)
        ]),
        new THREE.LineBasicMaterial({ color: 0xe7fcff, transparent: true, opacity: 0.9 })
      );
      security.add(scanBeam);

      network.clear();
      security.clear();

      const laptop = new THREE.Group();
      const laptopBodyMaterial = new THREE.MeshBasicMaterial({
        color: 0x07101b,
        transparent: true,
        opacity: 0.96
      });
      const screenFrameGeometry = new THREE.BoxGeometry(12.6, 7.4, 0.46);
      const screenFrame = new THREE.Mesh(screenFrameGeometry, laptopBodyMaterial);
      screenFrame.position.set(0, 1.3, 0);
      laptop.add(screenFrame);
      laptop.add(new THREE.LineSegments(
        new THREE.EdgesGeometry(screenFrameGeometry),
        new THREE.LineBasicMaterial({ color: 0x53758e, transparent: true, opacity: 0.62 })
      ));

      const displayCanvas = document.createElement("canvas");
      displayCanvas.width = 960;
      displayCanvas.height = 560;
      const displayContext = displayCanvas.getContext("2d");
      const displayGradient = displayContext.createLinearGradient(0, 0, 960, 560);
      displayGradient.addColorStop(0, "#071321");
      displayGradient.addColorStop(0.52, "#07101b");
      displayGradient.addColorStop(1, "#02060d");
      displayContext.fillStyle = displayGradient;
      displayContext.fillRect(0, 0, 960, 560);

      displayContext.strokeStyle = "rgba(48, 144, 191, 0.12)";
      displayContext.lineWidth = 1;
      for (let x = 0; x <= 960; x += 32) {
        displayContext.beginPath();
        displayContext.moveTo(x, 0);
        displayContext.lineTo(x, 560);
        displayContext.stroke();
      }
      for (let y = 0; y <= 560; y += 32) {
        displayContext.beginPath();
        displayContext.moveTo(0, y);
        displayContext.lineTo(960, y);
        displayContext.stroke();
      }

      const frameColor = "rgba(188, 225, 238, 0.64)";
      displayContext.strokeStyle = frameColor;
      displayContext.lineWidth = 3;
      [[78, 70, 38, 0, 0, 38], [882, 70, -38, 0, 0, 38], [78, 490, 38, 0, 0, -38], [882, 490, -38, 0, 0, -38]]
        .forEach(([x, y, horizontal, , , vertical]) => {
          displayContext.beginPath();
          displayContext.moveTo(x, y + vertical);
          displayContext.lineTo(x, y);
          displayContext.lineTo(x + horizontal, y);
          displayContext.stroke();
        });

      displayContext.fillStyle = "rgba(2, 8, 15, 0.68)";
      displayContext.fillRect(118, 103, 724, 354);
      displayContext.strokeStyle = "rgba(70, 202, 245, 0.42)";
      displayContext.lineWidth = 2;
      displayContext.strokeRect(118, 103, 724, 354);

      const shieldCenterX = 300;
      const shieldCenterY = 280;
      displayContext.save();
      displayContext.translate(shieldCenterX, shieldCenterY);
      displayContext.beginPath();
      displayContext.moveTo(0, -127);
      displayContext.lineTo(91, -88);
      displayContext.lineTo(80, 31);
      displayContext.quadraticCurveTo(64, 103, 0, 139);
      displayContext.quadraticCurveTo(-64, 103, -80, 31);
      displayContext.lineTo(-91, -88);
      displayContext.closePath();
      displayContext.fillStyle = "rgba(19, 96, 129, 0.16)";
      displayContext.fill();
      displayContext.strokeStyle = "#55d8fa";
      displayContext.lineWidth = 7;
      displayContext.shadowColor = "#1bb8f0";
      displayContext.shadowBlur = 20;
      displayContext.stroke();
      displayContext.shadowBlur = 0;

      displayContext.beginPath();
      displayContext.arc(0, -6, 28, Math.PI, 0);
      displayContext.lineTo(28, 57);
      displayContext.quadraticCurveTo(28, 68, 17, 68);
      displayContext.lineTo(-17, 68);
      displayContext.quadraticCurveTo(-28, 68, -28, 57);
      displayContext.closePath();
      displayContext.fillStyle = "#d8f8ff";
      displayContext.fill();
      displayContext.fillStyle = "#09243a";
      displayContext.beginPath();
      displayContext.arc(0, 35, 6, 0, Math.PI * 2);
      displayContext.fill();
      displayContext.fillRect(-3, 38, 6, 17);
      displayContext.restore();

      displayContext.fillStyle = "#c2d8e6";
      displayContext.beginPath();
      displayContext.arc(640, 165, 25, 0, Math.PI * 2);
      displayContext.arc(696, 146, 31, 0, Math.PI * 2);
      displayContext.arc(752, 165, 25, 0, Math.PI * 2);
      displayContext.fill();
      displayContext.beginPath();
      displayContext.ellipse(640, 201, 40, 20, 0, Math.PI, Math.PI * 2);
      displayContext.ellipse(696, 190, 52, 25, 0, Math.PI, Math.PI * 2);
      displayContext.ellipse(752, 201, 40, 20, 0, Math.PI, Math.PI * 2);
      displayContext.fill();

      displayContext.fillStyle = "#d9e7f0";
      displayContext.font = "bold 18px Consolas, monospace";
      displayContext.fillText("SECURE ACCESS", 576, 238);
      displayContext.fillStyle = "#6e899d";
      displayContext.font = "14px Consolas, monospace";
      displayContext.fillText("IDENTITY CHECK / 01", 576, 259);

      [[576, 280, "USER ID"], [576, 334, "ACCESS KEY"]].forEach(([x, y, label]) => {
        displayContext.fillStyle = "rgba(144, 179, 199, 0.18)";
        displayContext.fillRect(x, y, 208, 38);
        displayContext.strokeStyle = "rgba(112, 163, 191, 0.42)";
        displayContext.strokeRect(x, y, 208, 38);
        displayContext.fillStyle = "#8da9bb";
        displayContext.font = "13px Consolas, monospace";
        displayContext.fillText(label, x + 13, y + 24);
      });
      displayContext.fillStyle = "#123d59";
      displayContext.fillRect(625, 390, 111, 40);
      displayContext.strokeStyle = "#42c9f1";
      displayContext.strokeRect(625, 390, 111, 40);
      displayContext.fillStyle = "#d8f5ff";
      displayContext.font = "bold 17px Consolas, monospace";
      displayContext.fillText("LOGIN", 655, 416);

      displayContext.fillStyle = "rgba(81, 194, 231, 0.66)";
      displayContext.font = "12px Consolas, monospace";
      displayContext.fillText("ENCRYPTED SESSION   /   LOCAL NODE", 144, 433);

      const displayTexture = new THREE.CanvasTexture(displayCanvas);
      displayTexture.colorSpace = THREE.SRGBColorSpace;
      const display = new THREE.Mesh(
        new THREE.PlaneGeometry(12.12, 6.98),
        new THREE.MeshBasicMaterial({ map: displayTexture, transparent: true, opacity: 0.78 })
      );
      display.position.set(0, 1.3, 0.24);
      laptop.add(display);

      const baseGeometry = new THREE.BoxGeometry(14.2, 0.38, 3.1);
      const laptopBase = new THREE.Mesh(baseGeometry, laptopBodyMaterial);
      laptopBase.position.set(0, -2.62, 0.38);
      laptop.add(laptopBase);
      laptop.add(new THREE.LineSegments(
        new THREE.EdgesGeometry(baseGeometry),
        new THREE.LineBasicMaterial({ color: 0x46647d, transparent: true, opacity: 0.72 })
      ));

      const keyboardLines = [];
      for (let row = 0; row < 5; row++) {
        const keyY = -1.55 - row * 0.36;
        for (let column = 0; column < 20; column++) {
          const keyX = -5.5 + column * 0.58 + (row % 2) * 0.12;
          keyboardLines.push(
            keyX, keyY, 0.59, keyX + 0.4, keyY, 0.59,
            keyX + 0.4, keyY, 0.59, keyX + 0.4, keyY - 0.2, 0.59,
            keyX + 0.4, keyY - 0.2, 0.59, keyX, keyY - 0.2, 0.59,
            keyX, keyY - 0.2, 0.59, keyX, keyY, 0.59
          );
        }
      }
      const keyboardGeometry = new THREE.BufferGeometry();
      keyboardGeometry.setAttribute("position", new THREE.Float32BufferAttribute(keyboardLines, 3));
      laptop.add(new THREE.LineSegments(
        keyboardGeometry,
        new THREE.LineBasicMaterial({ color: 0x6da4c2, transparent: true, opacity: 0.3 })
      ));

      const touchpadGeometry = new THREE.PlaneGeometry(2.4, 0.72);
      const touchpad = new THREE.Mesh(
        touchpadGeometry,
        new THREE.MeshBasicMaterial({ color: 0x102033, transparent: true, opacity: 0.72 })
      );
      touchpad.position.set(0, -3.2, 0.59);
      laptop.add(touchpad);

      const laptopEdge = new THREE.Line(
        new THREE.BufferGeometry().setFromPoints([
          new THREE.Vector3(-7.3, -2.82, 0.5),
          new THREE.Vector3(7.3, -2.82, 0.5)
        ]),
        new THREE.LineBasicMaterial({ color: 0x28aee9, transparent: true, opacity: 0.7 })
      );
      laptop.add(laptopEdge);

      security.position.set(0, 1.3, 0.34);
      security.scale.set(1.04, 0.98, 1);
      security.add(orbit, scanBeam);
      laptop.add(security);
      laptop.position.set(-2.2, -0.8, 0);
      laptop.rotation.y = -0.13;
      laptop.rotation.x = 0.025;
      network.add(laptop);

      const roomLines = [];
      for (let index = 0; index < 6; index++) {
        const x = 7 + index * 2.4;
        roomLines.push(x, -13, -2.5, x + 4.5, 11, -2.5);
      }
      for (let index = 0; index < 7; index++) {
        const y = -10 + index * 3.1;
        roomLines.push(7, y, -2.5, 27, y + 1.5, -2.5);
      }
      const roomGeometry = new THREE.BufferGeometry();
      roomGeometry.setAttribute("position", new THREE.Float32BufferAttribute(roomLines, 3));
      network.add(new THREE.LineSegments(
        roomGeometry,
        new THREE.LineBasicMaterial({ color: 0x1883c4, transparent: true, opacity: 0.18 })
      ));
      const resize = () => {
        const width = window.innerWidth;
        const height = window.innerHeight;
        const mobile = width < 700;
        camera.aspect = width / height;
        camera.position.z = mobile ? 34 : 30;
        laptop.position.set(mobile ? 0 : -2.2, mobile ? -1.2 : -0.8, 0);
        laptop.scale.setScalar(mobile ? 0.68 : 1);
        camera.updateProjectionMatrix();
        renderer.setSize(width, height, false);
      };

      let scrollProgress = 0;
      let targetScroll = 0;
      const updateScroll = () => {
        const scrollableHeight = document.documentElement.scrollHeight - window.innerHeight;
        targetScroll = scrollableHeight > 0 ? window.scrollY / scrollableHeight : 0;
      };

      const render = (time) => {
        scrollProgress += (targetScroll - scrollProgress) * 0.035;
        if (!reducedMotion) {
          const scanPosition = Math.sin(time * 0.0008) * 2.4;
          network.rotation.y = scrollProgress * 0.28 + Math.sin(time * 0.00013) * 0.055;
          network.rotation.x = 0.025 + scrollProgress * 0.12 + Math.sin(time * 0.00018) * 0.018;
          network.position.y = scrollProgress * 1.8 + Math.sin(time * 0.00045) * 0.1;
          laptop.rotation.y = -0.13 + Math.sin(time * 0.00022) * 0.035;
          laptop.rotation.x = 0.025 + Math.sin(time * 0.00031) * 0.012;
          security.rotation.y = Math.sin(time * 0.0003) * 0.045;
          orbit.rotation.z = time * 0.00018;
          scanBeam.position.y = scanPosition;
        }
        renderer.render(scene, camera);
        window.requestAnimationFrame(render);
      };

      resize();
      updateScroll();
      window.addEventListener("resize", resize);
      window.visualViewport?.addEventListener("resize", resize);
      window.addEventListener("scroll", updateScroll, { passive: true });
      window.requestAnimationFrame(render);
    })
    .catch(() => {
      document.body.classList.add("cyber-background-fallback");
    });
}
// Grab DOM elements
const startShieldBtn = document.getElementById('startShieldBtn');
const videoElement = document.getElementById('sharedScreenVideo');
const canvasElement = document.getElementById('shieldCanvas');
const canvasCtx = canvasElement.getContext('2d');

let isShieldActive = false;

startShieldBtn.addEventListener('click', async () => {
    try {
        // 1. Request system screen share (Prompts user to share Entire Screen or Window)
        const mediaStream = await navigator.mediaDevices.getDisplayMedia({
            video: { cursor: "always" },
            audio: false
        });

        videoElement.srcObject = mediaStream;
        
        videoElement.onloadedmetadata = () => {
            videoElement.play();
            
            // Match canvas dimensions to the screen resolution
            canvasElement.width = videoElement.videoWidth;
            canvasElement.height = videoElement.videoHeight;
            
            isShieldActive = true;
            startShieldBtn.textContent = "🛡️ Shield Active (Sharing)";
            startShieldBtn.style.backgroundColor = "#10b981"; // Green

            // 2. Start the continuous frame processing loop
            requestAnimationFrame(processScreenStream);
        };

        // Handle user clicking "Stop Sharing" on the browser's native floating bar
        mediaStream.getVideoTracks()[0].onended = () => {
            stopShield();
        };

    } catch (error) {
        console.error("Screen sharing cancelled or denied:", error);
    }
});

function stopShield() {
    isShieldActive = false;
    startShieldBtn.textContent = "Enable Screen Privacy Shield";
    startShieldBtn.style.backgroundColor = "#2563eb";
    canvasCtx.clearRect(0, 0, canvasElement.width, canvasElement.height);
}

// 3. The Main Frame Loop (Runs ~30 times per second)
function processScreenStream() {
    if (!isShieldActive || videoElement.paused || videoElement.ended) return;

    // Draw the current live screen frame onto our hidden canvas
    canvasCtx.drawImage(videoElement, 0, 0, canvasElement.width, canvasElement.height);

    // ==========================================================
    // HOOK INTO YOUR EXISTING DETECTOR HERE:
    // Example: 
    // const sensitiveBoxes = window.yourDetectorFunction(canvasCtx, canvasElement.width, canvasElement.height);
    // 
    // sensitiveBoxes.forEach(box => {
    //     canvasCtx.fillStyle = '#000000'; // Apply blackout or blur
    //     canvasCtx.fillRect(box.x, box.y, box.width, box.height);
    // });
    // ==========================================================

    // Keep the loop running smoothly
    requestAnimationFrame(processScreenStream);
}