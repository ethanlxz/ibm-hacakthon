# Phase 1 Plan — PII Log Leak Detector MVP

## Overview

Build the working skeleton of the PII Log Leak Detector: a FastAPI backend that scans a demo Python codebase and log file for PII leaks, paired with a minimal HTML/JS dashboard that displays detected leaks in a results table. No fix application, no AST analysis — just detection and display.

All work lives under a new `pii-log-detector/` directory created from scratch.

---

## Sub-Task 1 — Project Scaffold

**Status:** `[x] done`

**Intent**
Create the directory layout and dependency files so every subsequent sub-task has a stable place to land. Nothing is implemented here — just the skeleton.

**Expected Outcomes**
- `pii-log-detector/` directory exists with the full folder tree from `plan.md § 1`
- `requirements.txt` lists: `fastapi`, `uvicorn[standard]`, `pydantic`
- `README.md` contains a one-paragraph description and the run command
- All `app/`, `demo_app/`, `logs/`, `static/`, `tests/` directories exist (with placeholder `__init__.py` or `.gitkeep` as appropriate)

**Todo List**
1. Create `pii-log-detector/` root directory
2. Create sub-directories: `app/`, `demo_app/`, `logs/`, `static/`, `tests/`
3. Add `app/__init__.py`, `demo_app/__init__.py`, `tests/__init__.py` (empty)
4. Write `requirements.txt`
5. Write `README.md` with project description and `uvicorn app.main:app --reload` run instruction

**Relevant Context**
- Target layout: `plan.md` § "1. Project Structure"
- Run command: `uvicorn app.main:app --reload`

---

## Sub-Task 2 — Pydantic Models

**Status:** `[x] done`

**Intent**
Define all shared data shapes in one place (`app/models.py`) so scanners and API routes use the same types throughout Phase 1. Doing this before writing any logic prevents type drift.

**Expected Outcomes**
- `app/models.py` exists and is importable
- `ScanRequest` model with `project_path: str` and `log_path: str`
- `PiiMatch` model with `pii_type`, `value`, `severity`, `source` (file + line), `log_file`, `log_line` fields
- `ScanResult` model with `status`, `total_leaks`, and `results: list[PiiMatch]`

**Todo List**
1. Create `app/models.py`
2. Define `ScanRequest` Pydantic model
3. Define `PiiMatch` Pydantic model (all fields nullable where not always present)
4. Define `ScanResult` Pydantic model

**Relevant Context**
- Field shapes come from `plan.md` § "5. Implement Log Scanner" (result JSON) and § "7. FastAPI Backend" (API output)
- Severity values: `"HIGH"`, `"MEDIUM"`, `"LOW"` (Phase 3 adds `"CRITICAL"` — leave as `str` for now)

---

## Sub-Task 3 — Demo App and Intentional Leaks

**Status:** `[x] done`

**Intent**
Create the synthetic codebase that the scanner will target. All four leak patterns from `plan.md` must be present so the scanner has real targets to find. All data is fictional.

**Expected Outcomes**
- `demo_app/customer.py` — `Customer` dataclass/model with `name`, `email`, `ic_number`, `card_number`, `account_number`; `__repr__` exposes all fields
- `demo_app/customer_service.py` — contains Leak 1 (direct IC log) and Leak 2 (whole object log)
- `demo_app/payment_service.py` — contains Leak 3 (exception with card payload)
- `demo_app/api_service.py` — contains Leak 4 (debug log of request dict)
- `logs/test.log` — a pre-generated log file with realistic lines that include all four PII types (email, IC, card number, phone); lines are the kind that would be produced by running the demo app

**Todo List**
1. Write `demo_app/customer.py` with `Customer` class and a `DEMO_CUSTOMERS` list of ≥2 fake records
2. Write `demo_app/customer_service.py` with Leak 1 and Leak 2
3. Write `demo_app/payment_service.py` with Leak 3
4. Write `demo_app/api_service.py` with Leak 4
5. Write `logs/test.log` with ≥40 lines; embed synthetic PII on at least 4 lines (one per type)

**Relevant Context**
- Leak patterns: `plan.md` § "3. Plant Intentional Leaks"
- Example customer: Alice Tan, `alice@example.com`, IC `S1234567D`, card `4111111111111111`
- Malaysian IC format: `YYMMDD-PB-###G` (12 digits, e.g. `991231-14-5678`) — use this format for the IC detector too
- Card validation: Luhn check required (see Sub-Task 4)

---

## Sub-Task 4 — PII Detectors

**Status:** `[x] done`

**Intent**
Implement all five regex-based PII detectors in `app/detectors.py`. Each returns a list of match dicts so both the log scanner and source scanner can use the same functions.

**Expected Outcomes**
- `app/detectors.py` exists with five functions: `detect_email`, `detect_ic`, `detect_credit_card`, `detect_account_number`, `detect_phone_number`
- Each function accepts a `text: str` and returns `list[dict]` with keys `type`, `value`, `severity`, `start`, `end`
- `detect_credit_card` applies a Luhn checksum after regex match; non-passing numbers are excluded
- All five detectors are covered by `tests/test_scanner.py` unit tests (true positive + true negative)

**Todo List**
1. Create `app/detectors.py`
2. Implement `detect_email` (regex: RFC-ish local + domain; severity `MEDIUM`)
3. Implement `detect_ic` (Malaysian NRIC 12-digit format `YYMMDD-PB-###G`; severity `HIGH`)
4. Implement `detect_credit_card` (major card BIN patterns; add Luhn validation; severity `HIGH`)
5. Implement `detect_account_number` (10–16 digit standalone number; severity `HIGH`)
6. Implement `detect_phone_number` (Malaysian `+60` / `01X` formats; severity `MEDIUM`)
7. Write unit tests in `tests/test_scanner.py` covering each detector (at minimum one hit and one miss per detector)

**Relevant Context**
- Return shape: `plan.md` § "4. Implement PII Detectors"
- Luhn algorithm: standard mod-10 checksum
- Account number pattern must not overlap with credit card pattern (use length/context heuristics)

---

## Sub-Task 5 — Log Scanner

**Status:** `[x] done`

**Intent**
Implement `scan_log_file(path)` in `app/scanner.py`. This is the primary detection path for Phase 1 — reading each log line and running all detectors against it.

**Expected Outcomes**
- `app/scanner.py` exists with `scan_log_file(path: str) -> list[dict]`
- Returns one result dict per match (not per line) — a line with two PII values produces two results
- Each result contains: `pii_type`, `value`, `severity`, `log_file`, `log_line`
- Running against `logs/test.log` returns ≥4 results

**Todo List**
1. Create `app/scanner.py`
2. Implement `scan_log_file`: open file, iterate lines with index, run all five detectors per line, collect results
3. Normalise result dicts to match `PiiMatch` field names (leave `source_file`/`source_line` as `None` for log results)
4. Add a smoke-test assertion in `tests/test_scanner.py` that `scan_log_file("logs/test.log")` returns ≥1 result

**Relevant Context**
- Result shape: `plan.md` § "5. Implement Log Scanner"
- Detectors imported from `app/detectors.py` (Sub-Task 4)

---

## Sub-Task 6 — Source Scanner

**Status:** `[x] done`

**Intent**
Implement `scan_source_files(path)` in `app/scanner.py` using text/regex matching (not AST — that is Phase 2). Flag logging statements that reference known PII field names or whole objects.

**Expected Outcomes**
- `scan_source_files(path: str) -> list[dict]` added to `app/scanner.py`
- Scans all `.py` files under `path` recursively
- Flags lines matching: `logger.info/debug/warning/error/exception(...)` or `print(...)` where the argument contains `.email`, `.ic_number`, `.card_number`, `.account_number`, a whole variable (f-string `{obj}`), or `request`/`payload` keywords
- Each result contains: `pii_type` (`"SOURCE_LEAK"`), `severity`, `source_file`, `source_line`, `snippet` (the flagged line, stripped)
- Running against `demo_app/` returns ≥4 results (one per planted leak)

**Todo List**
1. Add `scan_source_files` to `app/scanner.py`
2. Define the set of dangerous field name patterns (`ic_number`, `card_number`, `email`, `account_number`) and object/dict patterns
3. Walk `.py` files with `pathlib.Path.rglob`
4. For each line, check logger/print call + PII pattern; record match
5. Add a smoke test in `tests/test_scanner.py` that `scan_source_files("demo_app/")` returns ≥1 result

**Relevant Context**
- Patterns to flag: `plan.md` § "6. Implement Source Scanner"
- AST-based upgrade deferred to Phase 2

---

## Sub-Task 7 — FastAPI Backend

**Status:** `[x] done`

**Intent**
Wire the scanners behind a FastAPI app so the dashboard (Sub-Task 8) has real endpoints to call. In-memory result storage is sufficient for Phase 1.

**Expected Outcomes**
- `app/main.py` serves the five endpoints from `plan.md § 7`
- `GET /` serves `static/index.html`
- `POST /api/scan` calls both scanners, merges results, stores them in memory, returns `ScanResult`
- `GET /api/results` returns the most recent `ScanResult` (or empty if no scan run)
- `POST /api/fix` and `POST /api/rescan` return `{"status": "not_implemented"}` stubs — they are scaffolded here, implemented in Phase 2
- `uvicorn app.main:app --reload` starts without errors

**Todo List**
1. Create `app/main.py`
2. Mount `static/` as a `StaticFiles` directory and serve `index.html` at `GET /`
3. Implement `POST /api/scan` using `ScanRequest` input; call `scan_log_file` and `scan_source_files`; merge; return `ScanResult`
4. Implement `GET /api/results` returning stored last result
5. Add stub `POST /api/fix` and `POST /api/rescan`
6. Verify server starts with `uvicorn app.main:app --reload` (manual check or test with `TestClient`)

**Relevant Context**
- Endpoint specs: `plan.md` § "7. FastAPI Backend"
- Models from `app/models.py` (Sub-Task 2)
- Scanners from `app/scanner.py` (Sub-Tasks 5 & 6)
- StaticFiles: `fastapi.staticfiles.StaticFiles`

---

## Sub-Task 8 — Web Dashboard

**Status:** `[x] done`

**Intent**
Create the minimal HTML dashboard that calls `POST /api/scan`, shows the four summary cards, and renders detected leaks in a table. No fix application in Phase 1.

**Expected Outcomes**
- `static/index.html` renders with Tailwind CDN styles
- Header shows app title and subtitle
- "Scan Project" button triggers `POST /api/scan` via `fetch`
- Four summary cards update: total leaks, high severity count, medium count, low count
- Results table renders columns: Severity | PII Type | Masked Value | Log File | Source File | Line
- `static/app.js` contains all JS logic (no inline scripts)

**Todo List**
1. Create `static/index.html` with Tailwind CDN link and header section
2. Add summary card layout (four cards, values start at `—`)
3. Add results table skeleton with correct column headers
4. Create `static/app.js` — `scanProject()` function: POST to `/api/scan`, parse response, populate cards and table
5. Wire "Scan Project" button `onclick` to `scanProject()`
6. Add a simple masking helper in `app.js` to display masked values in the table (e.g. show first+last chars only)

**Relevant Context**
- UI layout: `plan.md` § "8. Basic Web Dashboard"
- Column list: Severity, PII Type, Masked Value, Log File, Source File, Line, Action
- Tailwind CSS via CDN (no build step)
- Masked display only — no fix endpoint called from Phase 1 UI

---

## Phase 1 Completion Criteria

All items below must be true before Phase 1 is considered done:

- [ ] `uvicorn app.main:app --reload` starts without errors from `pii-log-detector/`
- [ ] `POST /api/scan` with `{"project_path": "./demo_app", "log_path": "./logs/test.log"}` returns `total_leaks >= 3`
- [ ] At least 3 PII categories are detected (e.g. IC, card number, email)
- [ ] `GET http://localhost:8000` opens the dashboard
- [ ] Dashboard shows leak count and results table after clicking "Scan Project"
- [ ] Source filenames and line numbers appear for source-scan results
- [ ] All unit tests in `tests/test_scanner.py` pass with `pytest`
