/**
 * LogGuard — PII Log Leak Detector dashboard logic.
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
// Severity badge — dark theme
// ---------------------------------------------------------------------------

const SEVERITY_CLASS = {
  CRITICAL: "badge-critical",
  HIGH:     "badge-high",
  MEDIUM:   "badge-medium",
  LOW:      "badge-low",
};

function severityBadge(severity) {
  const cls = SEVERITY_CLASS[severity] || "badge-low";
  return `<span class="inline-block px-2.5 py-0.5 rounded-full text-xs font-semibold ${cls}">${severity}</span>`;
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
// Progress bar
// ---------------------------------------------------------------------------

function updateProgress(results) {
  const wrap = document.getElementById("progressWrap");
  const bar  = document.getElementById("progressBar");
  const lbl  = document.getElementById("progressLabel");
  if (!wrap || !bar) return;

  const total = results.length;
  const highCritical = results.filter(r => r.severity === "HIGH" || r.severity === "CRITICAL").length;
  const medium = results.filter(r => r.severity === "MEDIUM").length;

  wrap.classList.remove("hidden");

  if (total === 0) {
    bar.style.width = "100%";
    if (lbl) lbl.textContent = "CLEAN — No leaks detected";
  } else {
    // Weight findings: HIGH/CRITICAL count 3×, MEDIUM 1.5×, LOW 1×
    const weightedLeaks = highCritical * 3 + medium * 1.5 + (total - highCritical - medium);
    // Normalise against a baseline of 10 weighted units = 0 score,
    // so a single HIGH leak gives a score around 70 and it degrades smoothly.
    const score = Math.round(Math.max(0, 100 * Math.exp(-weightedLeaks / 10)));
    bar.style.width = score + "%";
    if (lbl) lbl.textContent = `Score ${score}/100`;
  }
}

// ---------------------------------------------------------------------------
// Render results
// ---------------------------------------------------------------------------

function renderResults(data) {
  const results = data.results || [];

  // Summary cards
  setText("cardTotal",  data.total_leaks ?? results.length);
  setText("cardHigh",   results.filter(r => r.severity === "HIGH" || r.severity === "CRITICAL").length);
  setText("cardMedium", results.filter(r => r.severity === "MEDIUM").length);
  setText("cardLow",    results.filter(r => r.severity === "LOW").length);

  // Result count label
  const countEl = document.getElementById("resultCount");
  if (countEl) {
    countEl.textContent = results.length === 0
      ? "No issues found"
      : `${results.length} issue${results.length !== 1 ? "s" : ""} found`;
  }

  updateProgress(results);

  const tbody = document.getElementById("resultsBody");
  tbody.innerHTML = "";

  if (results.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" class="px-5 py-12 text-center">
          <div class="flex flex-col items-center gap-2">
            <span class="text-2xl">✓</span>
            <span class="text-emerald-400 font-medium">No PII leaks detected</span>
            <span class="text-zinc-600 text-xs">All clear — your logs are clean</span>
          </div>
        </td>
      </tr>`;
    return;
  }

  for (const r of results) {
    const logFile    = r.log_file    ? r.log_file    : "—";
    const sourceFile = r.source_file ? r.source_file : "—";
    const line       = r.log_line ?? r.source_line ?? "—";

    const row = document.createElement("tr");
    row.className = "result-row border-b border-white/[0.04] transition-colors";
    row.innerHTML = `
      <td class="px-5 py-3.5">${severityBadge(r.severity)}</td>
      <td class="px-5 py-3.5 font-mono text-xs text-violet-300">${r.pii_type}</td>
      <td class="px-5 py-3.5 font-mono text-xs text-zinc-400">${maskValue(r.value)}</td>
      <td class="px-5 py-3.5 text-xs text-zinc-500 truncate max-w-xs" title="${logFile}">${logFile}</td>
      <td class="px-5 py-3.5 text-xs text-zinc-500 truncate max-w-xs" title="${sourceFile}">${sourceFile}</td>
      <td class="px-5 py-3.5 text-xs text-zinc-500">${line}</td>
      <td class="px-5 py-3.5">
        <button
          disabled
          class="text-xs px-3 py-1.5 rounded-lg border border-white/[0.08] text-zinc-600 cursor-not-allowed"
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
    setStatus(`Scan complete — ${data.total_leaks} leak(s) found`);
  } catch (err) {
    setStatus(`Error: ${err.message}`);
    console.error(err);
  } finally {
    btn.disabled = false;
    btn.textContent = "Scan Project";
  }
}
