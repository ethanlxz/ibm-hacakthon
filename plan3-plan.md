# Phase 3 Plan — Hackathon-Ready Security Platform

## Overview

Phases 1 and 2 are complete. The tool detects PII in logs, traces leaks to source
lines via AST, generates masking fixes, applies them in-place, and re-scans to
verify remediation.

Phase 3 transforms the working MVP into a polished security platform that looks
credible to developer, security, and compliance audiences. Every sub-task below
is independent and can be reviewed before the next one begins.

**Phases 1 and 2 artefacts that Phase 3 builds on:**

| File | Role |
|------|------|
| `app/main.py` | FastAPI app — new endpoints added here |
| `app/detectors.py` | PII detectors — severity values sourced here |
| `app/models.py` | Pydantic models — new fields added here |
| `app/scanner.py` | Log scanner |
| `app/source_tracer.py` | AST tracer + correlator |
| `app/masking.py` | Masking functions |
| `app/fixer.py` | Fix suggestion generator |
| `static/index.html` | Web dashboard — extended in sub-task 7 |
| `static/app.js` | Dashboard JS — extended in sub-task 7 |
| `tests/test_phase2.py` | Reference for test patterns |

---

## Sub-Task 1 — Severity Engine

**Status:** `[ ] pending`

### Intent

Replace the flat per-detector severity strings with a centrally evaluated severity
engine that can weight multiple signals. This gives the dashboard and report
meaningful HIGH / MEDIUM / LOW / CRITICAL labels that are consistently applied
everywhere.

### Expected Outcomes

- A new `app/severity.py` module with a `classify_severity(pii_type, context)` function.
- `CRITICAL` assigned to full payment-card numbers, auth tokens, and passwords.
- `HIGH` assigned to NRIC, passport, bank account numbers.
- `MEDIUM` assigned to email addresses and phone numbers.
- `LOW` assigned to names and internal identifiers.
- `PiiMatch` in `app/models.py` carries the severity from this engine (not hardcoded in each detector).
- Existing tests continue to pass.

### Todo List

- [ ] Create `app/severity.py` with a `SEVERITY_MAP` dict keyed on `pii_type` string.
- [ ] Add a `classify_severity(pii_type: str) -> str` function that returns `CRITICAL | HIGH | MEDIUM | LOW`.
- [ ] Update `app/detectors.py` to remove hardcoded severity and call `classify_severity()` instead.
- [ ] Update `app/models.py` `PiiMatch` to add a `severity` field if not already present.
- [ ] Add unit tests in `tests/test_phase3.py` covering each severity tier.

### Relevant Context

- Current hardcoded severities live in `app/detectors.py` inside each `detect_*()` return dict.
- `app/models.py` `PiiMatch` already has a `severity` field — verify it is populated end-to-end.

---

## Sub-Task 2 — Confidence Scoring

**Status:** `[ ] pending`

### Intent

Add a numeric confidence score (0.0–1.0) to each finding. Higher confidence
means fewer false positives surface first in the dashboard. This is a key
differentiator for a security tool.

### Expected Outcomes

- Each `PiiMatch` carries a `confidence: float` field (0.0–1.0).
- Score is computed by summing weighted signals: regex matched, expected field name
  present in source snippet, checksum valid (Luhn for cards), PII appears in a log
  context line.
- Dashboard displays confidence as a percentage next to each finding.

### Todo List

- [ ] Add `confidence: float` to `PiiMatch` in `app/models.py`.
- [ ] Create `compute_confidence(pii_type, value, source_snippet, field_name) -> float` in `app/severity.py` (or a new `app/confidence.py`).
- [ ] Implement four additive signals:
  - Regex matched: `+0.5` (always true when a finding is created)
  - Expected field name in source snippet: `+0.2` (check if `ic_number`, `card_number`, etc. appear)
  - Known checksum valid (Luhn for CARD_NUMBER): `+0.2`
  - Appears in log context string: `+0.1`
- [ ] Wire `compute_confidence()` into the scan pipeline in `app/main.py` so every match gets a score.
- [ ] Add unit tests to `tests/test_phase3.py` for each signal combination.

### Relevant Context

- Luhn helper already exists in `app/detectors.py` — reuse it rather than reimplementing.
- Pipeline assembly is in `app/main.py` lines 33–56 (the scan endpoint handler).

---

## Sub-Task 3 — Allow-list (.piiignore)

**Status:** `[ ] pending`

### Intent

Allow developers to suppress known-safe findings (test fixtures, example values)
so they are not repeatedly reported on every scan.

### Expected Outcomes

- A `.piiignore` file at the project root is respected.
- Lines in `.piiignore` are either file glob patterns or literal PII values.
- Any finding whose `log_file` path matches a glob, or whose `value` matches a
  literal entry, is silently excluded from scan results.
- If `.piiignore` does not exist the scanner proceeds without error.

### Todo List

- [ ] Create `app/allowlist.py` with `load_allowlist(path) -> AllowList` and `is_allowed(finding, allowlist) -> bool`.
- [ ] Support two rule types: glob path patterns (e.g. `tests/fixtures/*`) and literal value strings (e.g. `example@example.com`).
- [ ] Load the allowlist at the start of `POST /api/scan` (look for `.piiignore` in the scanned project path).
- [ ] Filter findings through `is_allowed()` before the response is built.
- [ ] Add a `GET /api/allowlist` endpoint that returns the currently loaded rules.
- [ ] Add unit tests in `tests/test_phase3.py` for glob matching and literal matching.

### Relevant Context

- Findings are assembled in `app/main.py` — filtering belongs after correlation.
- Glob matching: use `pathlib.PurePosixPath` with `fnmatch` from the standard library.

---

## Sub-Task 4 — Scan History

**Status:** `[ ] pending`

### Intent

Persist each scan result so the dashboard can show improvement over time.
This demonstrates to a hackathon audience that the tool drives down the leak count
across multiple fix-and-rescan cycles.

### Expected Outcomes

- Each completed scan is appended to `scan_history.json` in the project working directory.
- `GET /api/history` returns a list of past scans ordered newest-first, each with
  `scan_id`, `timestamp`, `total_leaks`, `status` (`PASS` / `FAIL`).
- Dashboard "History" view renders a simple trend table or sparkline.

### Todo List

- [ ] Create `app/history.py` with `append_scan(result: ScanResult) -> None` and `load_history() -> list[dict]`.
- [ ] Store history in `scan_history.json` (newline-delimited JSON or a JSON array).
- [ ] Call `append_scan()` at the end of both `POST /api/scan` and `POST /api/rescan`.
- [ ] Add `GET /api/history` endpoint in `app/main.py`.
- [ ] Extend the dashboard with a "History" section that lists past scans and leak counts.
- [ ] Add unit tests in `tests/test_phase3.py` for append/load round-trip.

### Relevant Context

- `ScanResult` in `app/models.py` already has `status`, `total_leaks`, `results`.
- Use `datetime.utcnow().isoformat()` for timestamps; no external dependency needed.

---

## Sub-Task 5 — Compliance Mapping

**Status:** `[ ] pending`

### Intent

Map each PII category to the relevant compliance frameworks it falls under. This
turns raw findings into business-relevant risk signals for a compliance audience.

### Expected Outcomes

- Each `PiiMatch` carries a `compliance_tags: list[str]` field listing relevant
  frameworks (e.g. `["PDPA", "PCI DSS"]`).
- Mapping is data-driven (a static dict), not hardcoded per detector.
- Dashboard shows compliance tags as badges on each finding row.
- No claim of "certified compliant" is made — tags are labelled "Potential exposure".

### Todo List

- [ ] Create `app/compliance.py` with a `COMPLIANCE_MAP` dict and `get_compliance_tags(pii_type: str) -> list[str]`.
- [ ] Define mappings:
  - `CARD_NUMBER` → `["PCI DSS"]`
  - `NRIC` → `["PDPA", "Internal banking policy"]`
  - `EMAIL` → `["PDPA"]`
  - `PHONE` → `["PDPA"]`
  - `ACCOUNT_NUMBER` → `["PDPA", "Internal banking policy"]`
- [ ] Add `compliance_tags: list[str]` to `PiiMatch` in `app/models.py`.
- [ ] Wire `get_compliance_tags()` into the scan pipeline.
- [ ] Render compliance tags as small badges in the dashboard results table.
- [ ] Add unit tests in `tests/test_phase3.py`.

### Relevant Context

- Pipeline assembly in `app/main.py` — add tag population alongside masking and fix suggestion.

---

## Sub-Task 6 — Export Security Report

**Status:** `[ ] pending`

### Intent

Produce a machine-readable report of the last scan so security or compliance teams
can archive or share results without manual copy-paste.

### Expected Outcomes

- `GET /api/report` returns a JSON document containing scan metadata and all findings.
- Report includes: `scan_id`, `timestamp`, `files_scanned`, `log_lines_scanned`,
  `leaks_detected`, `status` (`PASS` / `FAIL`), and the full `results` array.
- Dashboard has a "Download Report" button that triggers the endpoint and saves the file.

### Todo List

- [ ] Add `files_scanned: int` and `log_lines_scanned: int` to `ScanResult` in `app/models.py`.
- [ ] Populate those counts inside the scan pipeline.
- [ ] Add `GET /api/report` endpoint in `app/main.py` that serialises the last scan result.
- [ ] Return HTTP 404 with a clear message if no scan has been run yet.
- [ ] Add a "Download Report" button in `static/index.html` and wire it in `static/app.js`.
- [ ] Add unit tests in `tests/test_phase3.py` for the report endpoint.

### Relevant Context

- `GET /api/results` already returns cached results — `/api/report` wraps this with extra metadata.
- Use `response.headers["Content-Disposition"] = 'attachment; filename="pii-report.json"'` to trigger browser download.

---

## Sub-Task 7 — Final Dashboard Layout

**Status:** `[ ] pending`

### Intent

Polish the dashboard to match the Phase 3 design spec: add navigation tabs, a
security score panel, and wire the new Phase 3 features (history, compliance tags,
confidence score, download report) into the UI.

### Expected Outcomes

- Navigation bar with tabs: Dashboard, Scan, Findings, History, Settings.
- Dashboard tab shows a "PII Security Score" panel: `CLEAN` when 0 unresolved leaks,
  otherwise a count with severity breakdown.
- Summary metrics: files scanned, log lines scanned, previous leaks, fixed leaks.
- Findings table shows confidence percentage and compliance badges.
- History tab shows past scans in a table (scan number, timestamp, leak count, status).
- "Download Report" button is visible when a scan result exists.

### Todo List

- [ ] Add a top navigation bar to `static/index.html` with the five tabs.
- [ ] Implement tab switching in `static/app.js` (show/hide sections by tab).
- [ ] Build the "PII Security Score" summary card using existing summary data from `/api/results`.
- [ ] Add confidence percentage and compliance tag badges to each row in the findings table.
- [ ] Build the "History" tab content that fetches `GET /api/history` and renders a table.
- [ ] Add the "Download Report" button that fetches `GET /api/report` and saves the file.
- [ ] Ensure the dashboard degrades cleanly when no scan has been run yet.

### Relevant Context

- `static/index.html` and `static/app.js` are the only files changed in this sub-task.
- The existing Tailwind CDN + dark theme should be preserved and extended.

---

## Sub-Task 8 — CLI Interface

**Status:** `[ ] pending`

### Intent

Add a standalone CLI entry point so the tool can be used in a terminal without a
running web server. This supports CI/CD pipeline integration and offline demos.

### Expected Outcomes

- `python pii_scan.py scan <path> [--log <log_path>]` prints a formatted report.
- Clean scan exits with code `0` and prints `PASS`.
- Scan with leaks exits with code `1` and prints each finding with severity, type,
  log location, and source location.
- Output format matches the spec in `plan.md` Phase 3 section 8.

### Todo List

- [ ] Create `pii_scan.py` at the project root using `argparse`.
- [ ] Implement `cmd_scan(project_path, log_path)` that calls the same scanner functions used by the API (import directly from `app/`).
- [ ] Print summary line: `✓ N Python files scanned`, `✓ N log lines scanned`.
- [ ] Print each finding: severity, PII type, log location, source location.
- [ ] Exit with code `1` if any leaks found, `0` if clean.
- [ ] Add a brief CLI usage section to `README.md`.
- [ ] Add at least one smoke test in `tests/test_phase3.py` using `subprocess.run`.

### Relevant Context

- `app/scanner.py` `scan_log_file()` and `app/source_tracer.py` `scan_source_files_ast()` / `correlate()` are the pipeline functions to call directly.
- No new business logic required — this is purely a CLI wrapper around existing functions.

---

## Phase 3 Completion Criteria

Phase 3 is complete when:

- `[ ]` Severity engine classifies all PII types consistently.
- `[ ]` Confidence score is present on every finding.
- `[ ]` `.piiignore` suppresses known-safe values without error.
- `[ ]` Scan history persists across runs and is visible in the dashboard.
- `[ ]` Compliance tags appear on findings for PDPA, PCI DSS, and internal policy.
- `[ ]` `GET /api/report` returns a complete JSON report and the browser downloads it.
- `[ ]` Dashboard has navigation tabs, security score panel, and all Phase 3 UI elements.
- `[ ]` CLI prints a clean formatted report and exits with correct status codes.
- `[ ]` `pytest tests/ -v` passes with no new failures.
- `[ ]` The full demo flow in `plan.md` Phase 3 section 9 works end-to-end.
