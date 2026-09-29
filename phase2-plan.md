# Phase 2 Plan — Source Tracing and Automated Fixes

## Overview

Phase 1 produced a working scanner that detects PII in log files and flags risky logging statements
via regex. Phase 2 upgrades the tool into a real developer security tool by adding:

- AST-based source analysis to replace the regex source scanner
- Source-to-log correlation so each log finding is linked to the exact code line that caused it
- Masking functions so detected values are redacted in all outputs
- Fix suggestion generation that produces safe replacement code
- Implemented `POST /api/fix` and `POST /api/rescan` endpoints (currently stubs)
- An enhanced dashboard that shows the full trace and lets the user apply a fix and rerun

All work builds directly on the Phase 1 skeleton in `pii-log-detector/`. No new top-level
directories are needed.

---

## Sub-Task 1 — AST Source Analyser

**Status:** `[ ] pending`

**Intent**

Replace `scan_source_files` (regex line-by-line matching) with a proper Python AST walk. This
gives exact line numbers, identifies which variables are being logged, and can distinguish between
a direct field reference (`customer.ic_number`) and an entire object (`customer`). The result is
stored in the same `list[dict]` shape that the existing `scan_source_files` produced so the rest
of the system needs minimal changes.

**Expected Outcomes**

- `app/source_tracer.py` exists and is importable
- `scan_source_files_ast(path: str) -> list[dict]` walks every `.py` file under `path`
- For each `logger.*` / `print(...)` call found, the result dict includes:
  - `source_file` — relative file path
  - `source_line` — exact integer line number from AST
  - `logger_method` — `"info"`, `"debug"`, `"error"`, `"exception"`, `"warning"`, `"print"`
  - `variables` — list of variable/attribute names referenced in the call arguments
  - `pii_fields` — subset of `variables` that match known PII field names (`ic_number`, `card_number`, `email`, `account_number`, `phone`)
  - `logs_whole_object` — boolean: `True` when an argument is a plain variable (no attribute access), suggesting an entire object is logged
  - `snippet` — the source line text (stripped)
  - `pii_type` — `"SOURCE_LEAK"`
  - `severity` — `"HIGH"` when a PII field or whole object is detected, `"MEDIUM"` otherwise
- Running against `demo_app/` returns ≥ 4 results (one per planted leak)
- New unit tests in `tests/test_scanner.py` (or a new `tests/test_source_tracer.py`) cover:
  - direct field reference (`customer.ic_number`) is detected
  - whole-object reference (`customer` alone in f-string) is detected
  - a clean logging call with no PII is NOT flagged

**Todo List**

1. Create `app/source_tracer.py`
2. Implement `scan_source_files_ast(path: str) -> list[dict]` using `ast.parse` + a custom `ast.NodeVisitor` that visits `ast.Call` nodes
3. Inside the visitor, match callee patterns `logger.<method>` and `print`
4. For each matched call, walk the argument AST to extract all `ast.Attribute` and `ast.Name` nodes; populate `variables`, `pii_fields`, `logs_whole_object`
5. Map results to the same dict shape as the Phase 1 source scanner
6. Add unit tests

**Relevant Context**

- Phase 1 source scanner: `app/scanner.py` — `scan_source_files(path)` — the new function replaces this but must produce a compatible output shape
- Existing `PiiMatch` model: `app/models.py` — `source_file`, `source_line`, `snippet` fields already present
- Known PII field names (from Phase 1 source scanner patterns): `ic_number`, `card_number`, `email`, `account_number`, `phone`, `card`, `ic`
- Planted leaks: `demo_app/customer_service.py`, `demo_app/payment_service.py`, `demo_app/api_service.py`

---

## Sub-Task 2 — Source-to-Log Correlation

**Status:** `[ ] pending`

**Intent**

After the log scanner detects a PII value in a log line, this sub-task links that log finding back
to the source code statement that produced it. The correlation is best-effort: match the log
message text pattern against the string templates found in AST source results. A correlated
finding gets a `source_file` and `source_line`; an uncorrelated one keeps `None`.

**Expected Outcomes**

- `app/source_tracer.py` gains a `correlate(log_findings, source_findings) -> list[dict]` function
- For each log finding, the correlator checks whether any source finding's `snippet` text matches
  the log line (substring of the log message, normalised)
- When a match is found, the log finding's `source_file` and `source_line` are populated from
  the source finding
- A log finding that cannot be correlated remains unchanged (no error)
- The merged list is returned sorted by severity (HIGH first)
- `POST /api/scan` in `main.py` is updated to run correlation after scanning

**Todo List**

1. Add `correlate(log_findings: list[dict], source_findings: list[dict]) -> list[dict]` to `app/source_tracer.py`
2. Implement matching: for each log finding, iterate source findings and check if the source `snippet`'s f-string variable/template text appears in the log line
3. When matched, copy `source_file`, `source_line`, `logger_method` into the log finding
4. Update `POST /api/scan` in `app/main.py` to call `correlate` before building the `ScanResult`
5. Add a unit test that feeds a known log line + matching source snippet and verifies `source_file` is populated

**Relevant Context**

- `app/main.py` — `POST /api/scan` currently calls `scan_log_file` and `scan_source_files` then merges results; replace `scan_source_files` with `scan_source_files_ast` and add `correlate` call
- `app/models.py` — `PiiMatch.source_file` and `PiiMatch.source_line` are already nullable fields

---

## Sub-Task 3 — Masking Module

**Status:** `[ ] pending`

**Intent**

Create `app/masking.py` with one masking function per PII type. Masking is applied in the API
response and in the dashboard display. Having masking in the backend (not just the frontend JS
helper) means the `value` field in API responses always carries a redacted representation.

**Expected Outcomes**

- `app/masking.py` exists with five functions: `mask_email`, `mask_ic`, `mask_card`, `mask_account_number`, `mask_phone`
- Masking formats match `plan.md § Phase 2 § 3`:
  - `alice@example.com` → `a****@example.com`
  - `991231-14-5678` → `9*****-**-***8`  
  - `4111111111111111` → `************1111`
  - account number → last 4 digits visible, rest `*`
  - phone → last 4 digits visible, rest `*`
- `app/masking.py` exports `mask_value(pii_type: str, value: str) -> str` as a single dispatch function
- `PiiMatch` in `app/models.py` gains a `masked_value: Optional[str]` field
- `POST /api/scan` populates `masked_value` for every finding before returning
- Unit tests in `tests/test_scanner.py` or a new `tests/test_masking.py` cover each masking function (correct output format)

**Todo List**

1. Create `app/masking.py`
2. Implement `mask_email`, `mask_ic`, `mask_card`, `mask_account_number`, `mask_phone`
3. Implement `mask_value(pii_type, value)` dispatch function
4. Add `masked_value: Optional[str] = None` field to `PiiMatch` in `app/models.py`
5. Update `POST /api/scan` in `app/main.py` to call `mask_value` and populate `masked_value` on each result before returning
6. Write unit tests for all five masking functions

**Relevant Context**

- Masking format spec: `plan.md` § "Phase 2 — 3. Add Masking Functions"
- `PiiMatch` model: `app/models.py`
- PII type string values: `"EMAIL"`, `"NRIC"`, `"CARD_NUMBER"`, `"ACCOUNT_NUMBER"`, `"PHONE_NUMBER"`, `"SOURCE_LEAK"` — `mask_value` should handle all; `SOURCE_LEAK` can return the snippet as-is or `"[source]"`

---

## Sub-Task 4 — Fix Suggestion Generator

**Status:** `[ ] pending`

**Intent**

Create `app/fixer.py` that takes a `PiiMatch` (with `source_file`, `source_line`, and AST metadata)
and produces a suggested replacement code line. The suggestion is pattern-based: direct field
references get wrapped in the appropriate `mask_*()` call; whole-object logging gets rewritten as
`"customer_id=%s", obj.id`. No file is written here — this sub-task only generates the suggestion
string.

**Expected Outcomes**

- `app/fixer.py` exists with `suggest_fix(match: dict) -> str`
- For a finding where `pii_fields` contains `ic_number`:
  - input: `logger.info(f"Customer IC: {customer.ic_number}")`
  - output suggestion: `logger.info(f"Customer IC: {mask_ic(customer.ic_number)}")`
- For a finding where `logs_whole_object` is `True`:
  - input: `logger.info(f"Processing {customer}")`
  - output suggestion: `logger.info("Processing customer_id=%s", customer.id)`
- For findings with no AST metadata (log-only findings), `suggest_fix` returns `None`
- The `PiiMatch` model gains a `suggested_fix: Optional[str]` field
- `POST /api/scan` populates `suggested_fix` for each finding that has source context

**Todo List**

1. Create `app/fixer.py`
2. Implement `suggest_fix(match: dict) -> Optional[str]` — branch on `pii_fields` vs `logs_whole_object` vs no source context
3. For PII field matches, build the masked replacement using the correct `mask_*` function name
4. For whole-object matches, produce the `"obj_id=%s", obj.id` pattern
5. Add `suggested_fix: Optional[str] = None` to `PiiMatch` in `app/models.py`
6. Update `POST /api/scan` to call `suggest_fix` and populate `suggested_fix` on each result
7. Add unit tests for both fix branches (field-level fix, object-level fix, and no-source-context returns `None`)

**Relevant Context**

- Fix examples: `plan.md` § "Phase 2 — 4. Generate Fix Suggestions"
- `app/masking.py` (Sub-Task 3) provides the mask function names that suggestions reference
- `PiiMatch` model: `app/models.py`

---

## Sub-Task 5 — Implement Fix and Rescan Endpoints

**Status:** `[ ] pending`

**Intent**

Replace the two stub endpoints — `POST /api/fix` and `POST /api/rescan` — with real implementations.
`/api/fix` applies the suggested fix to the source file in-place (replacing the flagged line).
`/api/rescan` re-runs the full scan pipeline and returns the updated `ScanResult`.

**Expected Outcomes**

- `POST /api/fix` accepts `{"finding_id": str}` (where `finding_id` is the 0-based index into the last result list or a stable ID)
- Reads the target source file, replaces the flagged line with `suggested_fix`, writes the file back
- Returns `{"status": "fixed", "file": "...", "line": ...}`
- Returns `{"status": "no_fix_available"}` if the finding has no `suggested_fix`
- `POST /api/rescan` re-runs `scan_log_file` + `scan_source_files_ast` + `correlate` using the same paths as the last scan, updates the in-memory result, returns the new `ScanResult`
- `PiiMatch` model gains a stable `id` field (e.g. a UUID or sequential integer set at scan time) so the frontend can reference individual findings
- Unit tests cover: apply fix writes the correct line to the file; rescan after fix produces fewer results

**Todo List**

1. Add `id: str` field to `PiiMatch` (generated with `uuid4()` at scan time in `main.py`)
2. Implement `POST /api/fix` in `app/main.py`:
   a. Look up finding by `id` from the stored last result
   b. If `suggested_fix` is `None`, return `{"status": "no_fix_available"}`
   c. Read source file, replace line at `source_line - 1` with `suggested_fix`, write back
   d. Return `{"status": "fixed", "file": source_file, "line": source_line}`
3. Implement `POST /api/rescan` in `app/main.py`:
   a. Re-use the last `ScanRequest` paths stored in memory
   b. Run the full pipeline (log scan → AST source scan → correlate → mask → suggest)
   c. Return the new `ScanResult`
4. Store the last `ScanRequest` in memory at `POST /api/scan` time so `/api/rescan` can reuse it
5. Add integration tests (using FastAPI `TestClient`) for fix + rescan round-trip

**Relevant Context**

- `app/main.py` — existing `POST /api/fix` and `POST /api/rescan` stubs (lines 57–66)
- `app/models.py` — `PiiMatch` and `ScanResult`
- `app/fixer.py` (Sub-Task 4) — `suggest_fix`
- Fix endpoint spec: `plan.md` § "Phase 2 — 5. Fix API"

---

## Sub-Task 6 — Enhanced Dashboard

**Status:** `[ ] pending`

**Intent**

Upgrade the UI to show the full trace panel for each finding (log location → source location →
code snippet → suggested fix) and wire the "Apply Fix" button to `POST /api/fix`, followed by
an automatic rescan. The dashboard must reflect the updated leak count after each fix without
a full page reload.

**Expected Outcomes**

- Clicking a row in the results table expands (or slides open) a detail panel showing:
  - Masked PII value
  - Log file + line number
  - Source file + line number (if correlated)
  - Code snippet (`snippet` field)
  - Suggested fix code block (if available)
  - "Apply Fix" button (disabled when `suggested_fix` is `null`)
- Clicking "Apply Fix" sends `POST /api/fix` with the finding's `id`, then automatically calls `POST /api/rescan`, and re-renders the full results
- Summary cards update after every rescan
- A status message (e.g. "Fix applied — rescanning…") is shown during the async operation
- The "Scan Project" button remains functional for a fresh scan

**Todo List**

1. Update `static/index.html` to add a detail panel section below or beside the table (collapsed by default)
2. Update `static/app.js`:
   a. `renderResults()` — attach a row click handler that populates and shows the detail panel
   b. Add `applyFix(findingId)` function: POST to `/api/fix`, then POST to `/api/rescan`, then call `renderResults` with the new data
   c. Show/hide a loading indicator during async calls
   d. Render the `suggested_fix` value in a `<pre>` code block inside the panel
3. Ensure "Apply Fix" button is disabled / styled differently when `suggested_fix` is absent
4. Remove or repurpose the existing disabled "Apply Fix" column button from Phase 1

**Relevant Context**

- Phase 1 dashboard: `static/index.html`, `static/app.js` — existing `renderResults()` function and table structure
- UI spec: `plan.md` § "Phase 2 — 6. Enhanced UI"
- Fix + rescan API: Sub-Task 5 above
- `PiiMatch.id` added in Sub-Task 5 — use this as the identifier for the fix request

---

## Phase 2 Completion Criteria

All items below must be true before Phase 2 is considered done:

- [ ] `app/source_tracer.py` exists; `scan_source_files_ast("demo_app/")` returns ≥ 4 results with exact line numbers
- [ ] `POST /api/scan` response includes `source_file` and `source_line` populated on log findings that can be correlated
- [ ] `app/masking.py` exists; all five masking functions produce correct output; `masked_value` is populated in API responses
- [ ] `app/fixer.py` exists; `suggest_fix` returns a non-null string for findings with source context
- [ ] `POST /api/fix` applies the fix to the source file and returns `{"status": "fixed", ...}`
- [ ] `POST /api/rescan` re-runs the scan pipeline and returns a fresh `ScanResult`
- [ ] Dashboard detail panel shows the full trace (log location, source location, snippet, suggested fix)
- [ ] Clicking "Apply Fix" + auto-rescan reduces the visible leak count in the dashboard
- [ ] All existing Phase 1 tests continue to pass
- [ ] New Phase 2 tests pass (AST scanner, masking, fixer, fix endpoint, rescan endpoint)
