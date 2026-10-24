// Endpoint configuration
const ENDPOINT_URL = window.LINKGUARD_API_URL || localStorage.getItem("LINKGUARD_API_URL") || "https://veyl.onrender.com/analyze";
const PROXY_URL = "/api/analyze-proxy";
const LOCAL_FALLBACK_URL = "/api/scan";

const form = document.querySelector("#scan-form");
const input = document.querySelector("#url-input");
const messageInput = document.querySelector("#message-input");
const messageSection = document.querySelector("#message-section");
const messageDrawer = document.querySelector("#message-drawer");
const messageToggle = document.querySelector("#message-toggle");
const messageAdded = document.querySelector("#message-added");
const removeMessageButton = document.querySelector("#remove-message");
const button = document.querySelector("#scan-button");
const errorBox = document.querySelector("#form-error");
const emptyReport = document.querySelector("#report-empty");
const report = document.querySelector("#report-content");
const reportState = document.querySelector("#report-state");

const byId = (id) => document.getElementById(id);


function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = !message;
}

function assertScanReport(data) {
  const fields = [
    "submitted_url", "host", "verdict", "level", "risk_score", "score_label",
    "findings", "recommendation", "threat_intelligence", "analysis_mode", "agent", "scanned_at",
  ];
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("The backend returned an invalid scan report.");
  }

  const missing = fields.filter((field) => !(field in data));
  const validLevels = ["unknown", "low", "medium", "high"];
  const validAgentStatuses = ["complete", "not_configured", "missing_dependency", "unavailable"];
  const validIntelStatuses = ["not_configured", "unavailable", "clean", "match"];
  const intel = data.threat_intelligence;
  const agent = data.agent;
  const invalidFinding = Array.isArray(data.findings) && data.findings.some((finding) =>
    !finding || typeof finding.title !== "string" || typeof finding.detail !== "string" ||
    typeof finding.points !== "number" || typeof finding.severity !== "string");
  if (
    missing.length || !validLevels.includes(data.level) || typeof data.risk_score !== "number" ||
    !Array.isArray(data.findings) || invalidFinding || !intel || !validIntelStatuses.includes(intel.status) ||
    typeof intel.label !== "string" || !agent || !validAgentStatuses.includes(agent.status) ||
    typeof agent.provider !== "string"
  ) {
    throw new Error("The backend response does not match the scan report contract. Restart the backend and reload the page.");
  }
}

function apiErrorMessage(data) {
  const detail = data?.detail;
  if (typeof detail === "string") {
    if (/^\s*<!doctype\s+html\b|^\s*<html\b/i.test(detail)) {
      return "The analyzer returned a web page instead of scan data. Check the API endpoint and try again.";
    }
    return detail;
  }
  if (Array.isArray(detail)) {
    return detail.map((item) => {
      const field = Array.isArray(item.loc) ? item.loc.filter((part) => part !== "body").join(".") : "";
      const message = item.msg || "Invalid value";
      return field ? `${field}: ${message}` : message;
    }).join(" · ");
  }
  return "This URL could not be analyzed.";
}

function extractHost(urlStr) {
  try {
    const withScheme = /^https?:\/\//i.test(urlStr) ? urlStr : `http://${urlStr}`;
    return new URL(withScheme).hostname || urlStr;
  } catch {
    return urlStr;
  }
}

function normalizeScanReport(data, submittedUrl) {
  if (!data || typeof data !== "object") {
    throw new Error("Invalid response received from the endpoint.");
  }

  // If already matching canonical ScanReport, return as is
  if (
    "submitted_url" in data &&
    "findings" in data &&
    "verdict" in data &&
    "risk_score" in data &&
    "agent" in data
  ) {
    return data;
  }

  // Handle ScamShield AI / Render backend response
  const rawUrls = Array.isArray(data.urls) ? data.urls : [];
  const primaryUrl = rawUrls[0] || {};
  const actualUrl = primaryUrl.url || submittedUrl;
  const host = primaryUrl.hostname || extractHost(actualUrl);

  const riskAssessment = data.risk_assessment || {};
  const rawScore = typeof riskAssessment.score === "number" ? riskAssessment.score : 0;
  let rawLevel = String(riskAssessment.risk_level || "").toLowerCase();

  const verdictReport = String(data.verdict_report || "");

  // Extract verdict and level from verdict_report if present
  let verdict = "";
  const verdictMatch = verdictReport.match(/verdict:\s*([^\n\r.]+)/i);
  if (verdictMatch) {
    verdict = verdictMatch[1].trim();
    verdict = verdict.charAt(0).toUpperCase() + verdict.slice(1);
  }

  const levelMatch = verdictReport.match(/risk level:\s*(high|medium|low|unknown)/i);
  if (levelMatch && !rawLevel) {
    rawLevel = levelMatch[1].toLowerCase();
  }

  const validLevels = ["low", "medium", "high", "unknown"];
  const level = validLevels.includes(rawLevel)
    ? rawLevel
    : (rawScore > 3 ? "high" : rawScore > 0 ? "medium" : "low");

  if (!verdict) {
    verdict = level === "high" ? "Suspicious" : level === "medium" ? "Caution Advised" : "Clean Signals";
  }

  // Extract recommendations from report
  let recommendation = "";
  const recMatch = verdictReport.match(/recommended action:\s*([^\n\r]+(?:\n[^\n\r]+)*)/i);
  if (recMatch) {
    recommendation = recMatch[1].trim();
  } else {
    recommendation = level === "high"
      ? "Do not interact with or click this link. Block the sender."
      : level === "medium"
      ? "Proceed with caution. Verify the sender through an official channel before proceeding."
      : "The configured checks found no warning indicators. Always exercise caution with unknown messages.";
  }

  // Gather findings
  const findings = [];
  const seenTitles = new Set();

  if (Array.isArray(primaryUrl.findings)) {
    for (const f of primaryUrl.findings) {
      if (f && typeof f === "string" && !seenTitles.has(f)) {
        seenTitles.add(f);
        findings.push({
          title: f,
          detail: f,
          points: 1,
          severity: level === "high" ? "high" : level === "medium" ? "medium" : "low",
        });
      }
    }
  }

  if (Array.isArray(riskAssessment.evidence)) {
    for (const ev of riskAssessment.evidence) {
      if (ev && typeof ev === "string" && !seenTitles.has(ev) && !ev.toLowerCase().includes("no configured")) {
        seenTitles.add(ev);
        findings.push({
          title: ev,
          detail: ev,
          points: 1,
          severity: level === "high" ? "high" : level === "medium" ? "medium" : "low",
        });
      }
    }
  }

  return {
    submitted_url: actualUrl,
    host: host,
    verdict: verdict,
    level: level,
    risk_score: rawScore,
    score_label: `${level.toUpperCase()} RISK`,
    findings: findings,
    recommendation: recommendation,
    threat_intelligence: {
      status: "not_configured",
      label: "NOT CONFIGURED",
      detail: "",
    },
    analysis_mode: "cloud_api",
    agent: {
      status: "complete",
      provider: "ScamShield Gemma via Render",
      explanation: verdictReport || "The message and link were evaluated by ScamShield AI.",
    },
    scanned_at: new Date().toISOString(),
  };
}

function renderRecommendation(value, level) {
  const target = byId("recommendation-text");
  const text = String(value || "")
    .replace(/\*{1,2}/g, "")
    .replace(/(^|\n)\s*[-*]\s+/g, "$1")
    .replace(/\s+[-*]\s+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  const openingWarning = text.match(/^Do not click(?:\s+(?:the|this)\s+link)?[.!?]?\s*/i);
  const showClickWarning = level === "medium" || level === "high" || Boolean(openingWarning);

  target.replaceChildren();
  if (!showClickWarning) {
    target.textContent = text;
    return;
  }

  const emphasis = document.createElement("strong");
  emphasis.className = "warning-emphasis";
  emphasis.textContent = "DO NOT CLICK THIS LINK";
  target.append(emphasis);

  const remaining = openingWarning
    ? text.slice(openingWarning[0].length).replace(/^[\s,;:—-]+/, "")
    : text;
  if (remaining) target.append(document.createTextNode(` — ${remaining}`));
}

function renderAgentExplanation(value) {
  const target = byId("agent-explanation");
  const lines = String(value || "").split(/(\r?\n)/);
  let inRecommendedActions = false;
  let warningEmphasized = false;

  target.replaceChildren();
  for (const line of lines) {
    if (/^\r?\n$/.test(line)) {
      target.append(document.createTextNode(line));
      continue;
    }

    const cleanLine = line.replace(/\*{1,2}/g, "");
    if (/^\s*Recommended action\s*:/i.test(cleanLine)) {
      inRecommendedActions = true;
    }

    const warning = inRecommendedActions && !warningEmphasized
      ? cleanLine.match(/Do not click\b/i)
      : null;
    if (!warning) {
      target.append(document.createTextNode(cleanLine));
      continue;
    }

    const warningIndex = warning.index;
    target.append(document.createTextNode(cleanLine.slice(0, warningIndex)));
    const emphasis = document.createElement("strong");
    emphasis.className = "warning-emphasis";
    emphasis.textContent = "DO NOT CLICK";
    target.append(emphasis, document.createTextNode(cleanLine.slice(warningIndex + warning[0].length)));
    warningEmphasized = true;
  }
}

function renderReport(data) {
  assertScanReport(data);
  emptyReport.hidden = true;
  report.hidden = false;
  report.dataset.level = data.level;
  reportState.textContent = "ANALYSIS COMPLETE";
  reportState.classList.add("is-ready");

  byId("verdict-title").textContent = data.verdict;
  byId("verdict-overline").textContent = data.level === "unknown" ? "EVIDENCE INCOMPLETE" : `${data.level.toUpperCase()} ASSESSMENT`;
  byId("verdict-icon").textContent = data.level === "high" ? "!" : data.level === "medium" ? "~" : data.level === "low" ? "✓" : "?";
  const descriptions = {
    high: "One or more strong warning signals were found. Avoid interacting with this destination.",
    medium: "Some patterns deserve caution. Review the evidence before deciding what to do.",
    low: "The configured reputation source returned no known match. This does not prove the link is safe.",
    unknown: "The available checks are not enough to determine whether this link is safe.",
  };
  byId("verdict-description").textContent = descriptions[data.level] || descriptions.unknown;
  byId("risk-score").textContent = String(data.risk_score);
  byId("score-meter-fill").style.width = `${Math.max(0, Math.min(100, data.risk_score))}%`;
  byId("score-meter").setAttribute("aria-valuenow", String(data.risk_score));
  byId("score-caption").textContent = data.score_label;
  byId("scanned-url").textContent = data.submitted_url;
  byId("scan-time").textContent = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(data.scanned_at));
  renderRecommendation(data.recommendation, data.level);

  const agentReview = byId("agent-review");
  const agent = data.agent;
  const agentLabels = {
    complete: "EXPLANATION READY",
    not_configured: "NOT CONFIGURED",
    missing_dependency: "SETUP REQUIRED",
    unavailable: "TEMPORARILY UNAVAILABLE",
  };
  const agentMessages = {
    not_configured: "The evidence-based scan works without an AI provider. Add a Gemini API key to enable an explanation.",
    missing_dependency: "Install the optional backend AI dependencies to enable the hostname review.",
    unavailable: agent.message || "The optional AI explanation could not be generated. Your evidence-based scan is still complete.",
  };
  agentReview.dataset.status = agent.status || "unavailable";
  byId("agent-review-status").textContent = agentLabels[agent.status] || "STATUS UNKNOWN";
  renderAgentExplanation(agent.status === "complete" && agent.explanation
    ? agent.explanation
    : agentMessages[agent.status] || "The evidence-based scan is complete; the AI review status is unavailable.");

  const list = byId("findings-list");
  list.replaceChildren();
  byId("findings-count").textContent = `${data.findings.length} ${data.findings.length === 1 ? "FINDING" : "FINDINGS"}`;
  for (const finding of data.findings) {
    const row = document.createElement("article");
    row.className = "finding";
    row.dataset.severity = finding.severity;

    const symbol = document.createElement("span");
    symbol.className = "finding-symbol";
    symbol.setAttribute("aria-hidden", "true");
    symbol.textContent = finding.severity === "high" ? "!" : finding.severity === "medium" ? "~" : "·";

    const title = document.createElement("strong");
    title.className = "finding-title";
    title.textContent = finding.title;

    const detail = document.createElement("span");
    detail.className = "finding-detail";
    detail.textContent = finding.detail;

    const severity = document.createElement("span");
    severity.className = "finding-severity";
    severity.textContent = finding.severity;
    row.append(symbol, title, detail, severity);
    list.append(row);
  }
  report.scrollIntoView({ behavior: "smooth", block: "start" });
}

document.querySelector("#paste-button").addEventListener("click", async () => {
  showError("");
  try {
    if (!navigator.clipboard?.readText) throw new Error("Clipboard access is unavailable.");
    const clipboardText = await navigator.clipboard.readText();
    if (!clipboardText.trim()) throw new Error("Your clipboard is empty.");
    input.value = clipboardText.trim();
    input.focus();
  } catch (error) {
    showError(`${error.message || "Clipboard access was denied."} You can also paste with Ctrl+V.`);
  }
});

function setMessageDrawerOpen(isOpen) {
  messageDrawer.hidden = !isOpen;
  removeMessageButton.hidden = !isOpen;
  messageToggle.setAttribute("aria-expanded", String(isOpen));
  messageSection.classList.toggle("is-open", isOpen);
  updateMessageHeader();
}

function updateMessageHeader() {
  const hasMessage = Boolean(messageInput.value.trim());
  messageSection.classList.toggle("has-message", hasMessage);
  messageAdded.hidden = !(hasMessage && messageDrawer.hidden);
}

messageToggle.addEventListener("click", () => {
  setMessageDrawerOpen(messageDrawer.hidden);
});

messageInput.addEventListener("input", updateMessageHeader);

removeMessageButton.addEventListener("click", () => {
  messageInput.value = "";
  setMessageDrawerOpen(false);
  messageToggle.focus();
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  showError("");
  const url = input.value.trim();
  if (!url) {
    showError("Paste a URL before starting the analysis.");
    input.focus();
    return;
  }

  const extraMessage = messageInput.value.trim();
  const combinedMessage = extraMessage ? `${extraMessage}\n${url}` : url;
  const payload = {
    url: url,
    message: combinedMessage,
  };

  button.disabled = true;
  button.querySelector(".button-label").textContent = "Analyzing…";
  reportState.textContent = "CHECKING URL";

  try {
    let response;
    let endpointTried = ENDPOINT_URL;

    try {
      response = await fetch(ENDPOINT_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
    } catch (directErr) {
      console.warn(
        `Direct fetch to ${ENDPOINT_URL} failed (browser CORS/network limit). Retrying via proxy fallback...`,
        directErr
      );
      try {
        endpointTried = PROXY_URL;
        response = await fetch(PROXY_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
      } catch (proxyErr) {
        endpointTried = LOCAL_FALLBACK_URL;
        response = await fetch(LOCAL_FALLBACK_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: url, message: extraMessage }),
        });
      }
    }

    if (endpointTried !== LOCAL_FALLBACK_URL && !response.ok) {
      endpointTried = LOCAL_FALLBACK_URL;
      response = await fetch(LOCAL_FALLBACK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url, message: extraMessage }),
      });
    }

    let rawData;
    try {
      rawData = await response.json();
    } catch {
      throw new Error(`The endpoint (${endpointTried}) returned an unreadable response (${response.status}).`);
    }

    if (!response.ok) {
      throw new Error(apiErrorMessage(rawData));
    }

    const reportData = normalizeScanReport(rawData, url);
    renderReport(reportData);
  } catch (error) {
    reportState.textContent = "AWAITING URL";
    showError(
      error instanceof TypeError
        ? `The scanner endpoint (${ENDPOINT_URL}) could not be reached. Ensure the server is reachable or CORS is allowed.`
        : error.message || "The scan could not be completed."
    );
  } finally {
    button.disabled = false;
    button.querySelector(".button-label").textContent = "Inspect Link Safety";
  }
});

