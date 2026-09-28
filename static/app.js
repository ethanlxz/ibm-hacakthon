/**
 * PII Log Leak Detector — dashboard logic.
 */

// ---------------------------------------------------------------------------
// Masking helpers
// ---------------------------------------------------------------------------

function maskValue(value) {
  if (!value) return "—";
  if (value.length <= 4) return "****";
  const first = value[0];
  const last = value.slice(-2);
  const stars = "*".repeat(Math.max(value.length - 3, 4));
  return first + stars + last;
}

// ---------------------------------------------------------------------------
// Severity badge
// ---------------------------------------------------------------------------

const SEVERITY_CLASS = {
  HIGH:   "bg-red-100 text-red-700",
  MEDIUM: "bg-yellow-100 text-yellow-700",
  LOW:    "bg-green-100 text-green-700",
};

function severityBadge(severity) {
  const cls = SEVERITY_CLASS[severity] || "bg-gray-100 text-gray-600";
  return `<span class="inline-block px-2 py-0.5 rounded text-xs font-semibold ${cls}">${severity}</span>`;
}

// ---------------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------------

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function setStatus(msg) {
  setText("scanStatus", msg);
}

// ---------------------------------------------------------------------------
// Render results
// ---------------------------------------------------------------------------

function renderResults(data) {
  const results = data.results || [];

  // Update summary cards
  setText("cardTotal", data.total_leaks ?? results.length);
  setText("cardHigh",   results.filter(r => r.severity === "HIGH").length);
  setText("cardMedium", results.filter(r => r.severity === "MEDIUM").length);
  setText("cardLow",    results.filter(r => r.severity === "LOW").length);

  const tbody = document.getElementById("resultsBody");
  tbody.innerHTML = "";

  if (results.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="px-4 py-8 text-center text-green-600 font-medium">✓ No PII leaks detected.</td></tr>`;
    return;
  }

  for (const r of results) {
    const logFile    = r.log_file    ? `${r.log_file}` : "—";
    const sourceFile = r.source_file ? `${r.source_file}` : "—";
    const line       = r.log_line ?? r.source_line ?? "—";

    const row = document.createElement("tr");
    row.className = "hover:bg-gray-50 transition-colors";
    row.innerHTML = `
      <td class="px-4 py-3">${severityBadge(r.severity)}</td>
      <td class="px-4 py-3 font-mono text-xs text-gray-700">${r.pii_type}</td>
      <td class="px-4 py-3 font-mono text-xs text-gray-600">${maskValue(r.value)}</td>
      <td class="px-4 py-3 text-xs text-gray-500 truncate max-w-xs" title="${logFile}">${logFile}</td>
      <td class="px-4 py-3 text-xs text-gray-500 truncate max-w-xs" title="${sourceFile}">${sourceFile}</td>
      <td class="px-4 py-3 text-xs text-gray-500">${line}</td>
      <td class="px-4 py-3">
        <button
          disabled
          class="text-xs px-3 py-1 rounded border border-gray-200 text-gray-400 cursor-not-allowed"
          title="Fix application available in Phase 2"
        >Apply Fix</button>
      </td>
    `;
    tbody.appendChild(row);
  }
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

async function scanProject() {
  const btn = document.getElementById("scanBtn");
  btn.disabled = true;
  btn.textContent = "Scanning…";
  setStatus("Running scan…");

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        project_path: "./demo_app",
        log_path: "./logs/test.log",
      }),
    });

    if (!response.ok) {
      throw new Error(`Server returned ${response.status}`);
    }

    const data = await response.json();
    renderResults(data);
    setStatus(`Scan complete — ${data.total_leaks} leak(s) found.`);
  } catch (err) {
    setStatus(`Error: ${err.message}`);
    console.error(err);
  } finally {
    btn.disabled = false;
    btn.textContent = "Scan Project";
  }
}
