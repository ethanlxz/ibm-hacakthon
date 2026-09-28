# BobGuard — PII Log Leak Detector

> **Built with IBM Bob** · Python 3.12 · FastAPI · Tailwind CSS

BobGuard is a developer security tool that catches personally identifiable information (PII) leaking through application logs and source code **before those logs ever reach production**. It was scaffolded, planned, implemented, and refined entirely through IBM Bob — from high-level vision through detailed phase planning, code execution, test authoring, and iterative fixing — making it a working demonstration of AI-assisted secure software development.

---

## Problem Statement

Application logs are one of the most common — and least guarded — vectors for PII exposure. A developer writes an innocent-looking line:

```python
logger.info(f"Processing {customer}")
```

And silently, every request logs a customer's full name, IC number, credit card number, email address, and phone number to a flat file that may be shipped to a log aggregator, indexed by a SIEM, retained for years, or accessed by support staff who have no business seeing raw card data.

This is not a hypothetical. Payment card industry audits, PDPA investigations, and banking security reviews regularly surface exactly this class of finding. The problem is invisible to static linters, ignored by most CI pipelines, and only discovered after a breach or audit — at which point the remediation cost is orders of magnitude higher than prevention.

**BobGuard solves the prevention side.** It gives a developer a single command to scan their codebase and logs, see exactly where PII is leaking, understand which source line caused it, and apply a fix — all within a clean web dashboard.

---

## PII Categories Detected

| Type | Example | Severity |
|------|---------|----------|
| Malaysian NRIC | `991231-14-5678` | HIGH |
| Credit / debit card number | `4111111111111111` | HIGH |
| Bank account number | `1234567890` | HIGH |
| Email address | `alice@example.com` | MEDIUM |
| Malaysian phone number | `+60123456789` | MEDIUM |

Credit card numbers are validated using the **Luhn checksum** after regex matching, eliminating false positives from random digit sequences.

---

## How the Solution Works

```
┌─────────────────────────────────────────────────────────────────┐
│                       POST /api/scan                            │
│                                                                 │
│   project_path: ./demo_app      log_path: ./logs/test.log      │
└──────────────────────┬──────────────────┬───────────────────────┘
                       │                  │
            ┌──────────▼──────┐  ┌────────▼──────────┐
            │  AST Source     │  │   Log Scanner     │
            │  Scanner        │  │   (scanner.py)    │
            │ (source_tracer) │  └────────┬──────────┘
            └──────────┬──────┘           │
                       │           Reads .log line
            ast.parse() walk        by line
            visits Call nodes        │
            → logger.*() / print()   │
            → extracts variables,    Runs all 5 PII
              pii_fields,            detectors on
              logs_whole_object      each line
                       │                  │
                       └────┬─────────────┘
                            │
                   ┌────────▼────────┐
                   │   app/detectors │
                   │  detect_email() │
                   │  detect_ic()    │
                   │  detect_credit_ │
                   │    card() +Luhn │
                   │  detect_account │
                   │    _number()    │
                   │  detect_phone() │
                   └────────┬────────┘
                            │
                   ┌────────▼────────┐
                   │   correlate()   │
                   │ (source_tracer) │
                   │ links log hits  │
                   │ → source lines  │
                   └────────┬────────┘
                            │
                   ┌────────▼────────┐
                   │  mask_value()   │
                   │  (masking.py)   │
                   │ redacts PII in  │
                   │ API responses   │
                   └────────┬────────┘
                            │
                   ┌────────▼────────┐
                   │  suggest_fix()  │
                   │  (fixer.py)     │
                   │ generates safe  │
                   │ replacement code│
                   └────────┬────────┘
                            │
                   ┌────────▼────────┐
                   │  PiiMatch list  │
                   │  (models.py)    │
                   │  id, pii_type,  │
                   │  masked_value,  │
                   │  suggested_fix  │
                   └────────┬────────┘
                            │
                   ┌────────▼────────┐
                   │  ScanResult     │
                   │  returned as    │
                   │  JSON + stored  │
                   │  in memory      │
                   └────────┬────────┘
                            │
                   ┌────────▼────────┐
                   │  Dashboard      │
                   │  static/        │
                   │  index.html     │
                   │  + app.js       │
                   │  detail panel,  │
                   │  Apply Fix,     │
                   │  auto-rescan    │
                   └─────────────────┘
```

### Two scan modes

**Log scanner** — opens `.log` files and runs all five PII detectors against every line. Returns the PII type, masked value, file path, and exact line number of each hit.

**AST source scanner** (`source_tracer.py`) — replaces the Phase 1 regex source scanner. Parses every `.py` file under the target directory using Python's built-in `ast` module. A custom `NodeVisitor` walks all `ast.Call` nodes and identifies any `logger.*()` or `print()` call whose arguments reference a known PII field name (`.ic_number`, `.card_number`, `.email`, `.account_number`, `.phone`), a whole-object f-string interpolation (`{customer}`), or a dangerous variable (`payload`, `request_data`, `error`, etc.). This produces exact line numbers and structured metadata — `pii_fields`, `logs_whole_object`, `variables` — that the masking and fix modules consume downstream.

**Source-to-log correlation** — after both scanners run, `correlate()` links each log finding back to the source statement that produced it using token-based matching between the source snippet and the log line. When a match is found, `source_file` and `source_line` are populated on the log finding.

All findings are then passed through `mask_value()` (producing `masked_value`) and `suggest_fix()` (producing `suggested_fix`) before the `ScanResult` is returned. Both scan modes produce `PiiMatch` records sharing the same Pydantic model, so the API response and dashboard treat log-origin and source-origin findings uniformly.

---

## Landing Page

![BobGuard landing page — "Stop PII before it reaches your logs" hero with nav, open dashboard CTA, and compliance trust badges](screenshots/Screenshot%202026-09-28%20202224.png)

---

## Dashboard

![PII Leak Detection dashboard showing 47 leaks found, severity breakdown, security score, and detected leaks table](screenshots/Screenshot%202026-09-28%20201932.png)

---

## Project Structure

```
pii-log-detector/
│
├── app/
│   ├── main.py           # FastAPI application — 5 endpoints
│   ├── scanner.py        # scan_log_file() + scan_source_files()
│   ├── source_tracer.py  # AST-based scanner + source-to-log correlator (Phase 2)
│   ├── masking.py        # PII masking functions (Phase 2)
│   ├── fixer.py          # Fix suggestion generator (Phase 2)
│   ├── detectors.py      # 5 PII detector functions + Luhn helper
│   └── models.py         # ScanRequest, PiiMatch, ScanResult (Pydantic)
│
├── demo_app/             # Synthetic codebase with intentional leaks
│   ├── customer.py       # Customer dataclass + DEMO_CUSTOMERS seed data
│   ├── customer_service.py    # Leak 1: direct IC log, Leak 2: whole object
│   ├── payment_service.py     # Leak 3: exception with card payload
│   └── api_service.py         # Leak 4: debug log of request dict
│
├── logs/
│   └── test.log          # Pre-generated log with embedded PII
│
├── static/
│   ├── index.html        # Tailwind CSS dashboard
│   └── app.js            # scanProject(), detail panel, Apply Fix, rescan
│
├── tests/
│   └── test_scanner.py   # Unit + smoke + Phase 2 integration tests
│
├── plan.md               # Full 3-phase project vision
├── phase1-plan.md        # Detailed sub-task breakdown for Phase 1
├── phase2-plan.md        # Detailed sub-task breakdown for Phase 2
├── requirements.txt
└── README.md
```

---

## Phase 2 Features

### AST-based source analysis

The Phase 1 regex scanner is replaced by a proper Python AST walk in `source_tracer.py`. Each risky log call produces a structured finding with:

- `pii_fields` — list of PII-sensitive attribute names found in the call arguments (e.g. `["ic_number"]`)
- `logs_whole_object` — `true` when a bare variable (not an attribute) is interpolated, indicating an entire object is logged
- `variables` — full list of variable and attribute names referenced in the call
- `snippet` — the exact source line text, stripped of leading whitespace
- `source_line` — exact integer line number from the AST (not approximate)

The visitor detects all six logging methods (`info`, `debug`, `warning`, `error`, `exception`, `print`) and recognises dangerous variable names (`payload`, `request_data`, `request`, `error`, `customer`, `user`, `token`, `password`, `secret`) as whole-object risks even when passed as positional arguments (e.g. `logger.exception(error)`).

### Source-to-log correlation

`correlate()` in `source_tracer.py` links log findings to the source statement that produced them. The matcher extracts meaningful tokens (≥ 4 characters, not Python keywords) from the source snippet and checks whether any appear in the log line. When matched, `source_file`, `source_line`, and `logger_method` are copied into the log finding. Unmatched log findings are returned unchanged.

### PII masking

`masking.py` provides five masking functions and a single `mask_value(pii_type, value)` dispatch entry point. Every `PiiMatch` returned by the API now includes a `masked_value` field — raw PII is never surfaced in API responses.

| PII Type | Raw | Masked |
|----------|-----|--------|
| NRIC | `991231-14-5678` | `9*****-**-***8` |
| CARD_NUMBER | `4111111111111111` | `************1111` |
| ACCOUNT_NUMBER | `123456789012` | `********9012` |
| EMAIL | `alice@example.com` | `a****@example.com` |
| PHONE_NUMBER | `+60123456789` | `*******6789` |

### Fix suggestions

`fixer.py` provides `suggest_fix(match)` which generates a safe replacement code line for any source finding. Two patterns are handled:

**Direct PII field reference** — wraps the field access in the appropriate `mask_*()` call:
```python
# Before
logger.info(f"Customer IC: {customer.ic_number}")
# Suggested fix
logger.info(f"Customer IC: {mask_ic(customer.ic_number)}")
```

**Whole-object logging** — rewrites to log only the object's id:
```python
# Before
logger.info(f"Processing {customer}")
# Suggested fix
logger.info("Processing customer_id=%s", customer.id)
```

Log-only findings (no source context) return `None` for `suggested_fix`.

### Apply Fix + rescan workflow

`POST /api/fix` reads the target source file, replaces the flagged line in-place with `suggested_fix`, and returns `{"status": "fixed", "file": "...", "line": ...}`. If a finding has no `suggested_fix`, it returns `{"status": "no_fix_available"}`.

`POST /api/rescan` re-runs the full scan pipeline — log scan → AST source scan → correlate → mask → suggest — using the same paths as the last scan, and returns a fresh `ScanResult`. The dashboard calls rescan automatically after every applied fix and re-renders the results without a page reload.

### Enhanced dashboard

The Phase 2 dashboard adds a detail panel that expands when a row is clicked:

```
HIGH — NRIC Leak

Detected:    9*****-**-***8
Log:         logs/test.log:4
Source:      demo_app/customer_service.py:17
Code:        logger.info(f"Verifying identity for IC: {customer.ic_number}")
Suggested:   logger.info(f"Verifying identity for IC: {mask_ic(customer.ic_number)}")

[Apply Fix]
```

Clicking **Apply Fix** sends `POST /api/fix`, then automatically triggers `POST /api/rescan`, and re-renders the summary cards and results table. A status message ("Fix applied — rescanning…") is shown during the async operation.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Serves the web dashboard |
| `POST` | `/api/scan` | Runs full pipeline (log + AST source scan → correlate → mask → suggest), returns `ScanResult` |
| `GET` | `/api/results` | Returns the most recent scan result |
| `POST` | `/api/fix` | Applies `suggested_fix` to the source file in-place |
| `POST` | `/api/rescan` | Re-runs the full scan pipeline with the last scan's paths |

### `POST /api/scan`

Request:
```json
{
  "project_path": "./demo_app",
  "log_path": "./logs/test.log"
}
```

Response:
```json
{
  "status": "completed",
  "total_leaks": 12,
  "results": [
    {
      "id": "a3f1c2d4-...",
      "pii_type": "NRIC",
      "value": "991231-14-5678",
      "masked_value": "9*****-**-***8",
      "severity": "HIGH",
      "log_file": "logs/test.log",
      "log_line": 4,
      "source_file": "demo_app/customer_service.py",
      "source_line": 17,
      "suggested_fix": null
    },
    {
      "id": "b7e9d0f2-...",
      "pii_type": "SOURCE_LEAK",
      "value": "logger.info(f\"Verifying identity for IC: {customer.ic_number}\")",
      "masked_value": "logger.info(f\"Verifying identity for IC: {customer.ic_number}\")",
      "severity": "HIGH",
      "source_file": "demo_app/customer_service.py",
      "source_line": 17,
      "log_file": null,
      "log_line": null,
      "suggested_fix": "logger.info(f\"Verifying identity for IC: {mask_ic(customer.ic_number)}\")"
    }
  ]
}
```

### `POST /api/fix`

Request:
```json
{
  "finding_id": "b7e9d0f2-..."
}
```

Response (fix applied):
```json
{
  "status": "fixed",
  "file": "demo_app/customer_service.py",
  "line": 17
}
```

Response (no fix available):
```json
{
  "status": "no_fix_available"
}
```

### `POST /api/rescan`

No request body required. Re-uses the paths from the last `POST /api/scan` call.

Response: same shape as `POST /api/scan`.

---

## Setup and Run

### Prerequisites

- Python 3.12+
- Git

### Install

```bash
git clone <repo-url>
cd pii-log-detector

python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### Run the server

```bash
uvicorn app.main:app --reload
```

Open **http://localhost:8000** in your browser, then click **Scan Project**.

### Run the tests

```bash
pytest tests/ -v
```

Expected output: **18 passed**.

---

## How This Was Built with IBM Bob

The entire project — from the first line of planning to the last line of code — was produced through IBM Bob. Here is the exact workflow used.

### Step 1 — Generate the 3-phase project vision (Plan mode)

The starting point was a single high-level prompt to Bob in **Plan mode**:

> *"I want to build a developer security tool that scans Python source code and application logs for leaked PII such as Malaysian IC numbers, credit card numbers, emails, bank account numbers, and phone numbers. The tool should identify the leak, trace it to the source line, suggest a masking fix, apply the fix, and let me rerun the scan. Generate a full project plan broken into 3 phases."*

Bob produced `plan.md` — a three-phase roadmap covering the full scope from scanner MVP through AST-based source tracing and automated fixing, all the way to a hackathon-ready security platform with compliance mapping, confidence scoring, scan history, and a CLI.

### Step 2 — Generate detailed phase plans (Plan mode)

With the high-level vision in place, Bob was asked — still in **Plan mode** — to produce a detailed, executable breakdown for each phase individually:

> *"Based on plan.md, generate a detailed implementation plan for Phase 1 as phase1-plan.md."*

Bob produced `phase1-plan.md`: a structured document with a sub-task for each component (models, demo app, detectors, log scanner, source scanner, API, dashboard), each sub-task containing an intent statement, a list of exact expected outcomes, a concrete todo list, and the relevant files and context needed to execute it.

The same prompt pattern was repeated for Phase 2:

> *"Based on plan.md, generate a detailed implementation plan for Phase 2 as phase2-plan.md."*

This produced `phase2-plan.md` — covering AST source analysis, source-to-log correlation, masking functions, fix suggestion generation, the fix and rescan endpoints, and the enhanced dashboard.

### Step 3 — Execute each phase plan (Agent mode)

With the detailed plans in hand, Bob was switched to **Agent mode** and given a direct execution prompt:

> *"Implement the phase1-plan.md into the pii-log-detector."*

Bob read every relevant existing file, worked through each sub-task in order, created all new files, updated existing ones, and ran `pytest` to verify the results before reporting completion.

The same pattern was repeated for Phase 2:

> *"Implement the phase2-plan.md into the pii-log-detector."*

Bob read `phase2-plan.md`, read all existing source files to understand the Phase 1 baseline, created `source_tracer.py`, `masking.py`, and `fixer.py`, rewrote `models.py` and `main.py` to wire the new modules in, and updated the dashboard.

### Why this workflow matters

The three-step pattern — **high-level vision → detailed phase plan → agent execution** — is not just a convenience. It produces better results than a single "build this whole thing" prompt because:

- **Plan mode** forces a structured decomposition before any code is written. Each sub-task has an intent, concrete outcomes, and acceptance criteria, which gives the agent a precise target.
- **Detailed phase plans** act as durable specifications. They can be reviewed, adjusted, or handed to a different agent session without losing context.
- **Agent mode execution** against a written plan produces focused, minimal changes. The agent traces every edit back to a specific sub-task requirement rather than improvising scope.

This mirrors the **Detect → Trace → Explain → Fix → Verify** loop that BobGuard itself implements for PII leaks — the same disciplined, step-by-step approach applied to the development process itself.

---

## Feasibility

BobGuard is built entirely on stable, widely-adopted components with no proprietary dependencies, no external services, and no model inference at runtime. Each design choice was made to keep the tool usable by a single developer on a local machine with no special infrastructure.

### Technical feasibility

| Concern | Approach | Why it is realistic |
|---------|----------|---------------------|
| PII detection accuracy | Regex + Luhn checksum | NRIC, card, email, phone, and account patterns are well-defined. Luhn validation eliminates the majority of false-positive card hits from random digit sequences. Accuracy is high for structured PII categories. |
| Source leak detection | Text-pattern matching (Phase 1), Python `ast` (Phase 2) | Python's built-in `ast` module parses real source reliably without external parsers. Field-name heuristics (`ic_number`, `card_number`, etc.) cover the most common leak patterns in real codebases. |
| Automated fix application | In-place file rewriting via `fixer.py` | Fixes are simple string substitutions on a known line number — wrapping a field reference in a masking function call. This is deterministic and reversible with version control. |
| Performance at scale | Line-by-line log streaming, `pathlib.rglob` traversal | No full file is loaded into memory. A codebase of hundreds of files and log files of hundreds of thousands of lines can be scanned in seconds on commodity hardware. |
| API surface | FastAPI + Uvicorn | Async Python HTTP server. No separate database, no message queue, no container required. State is held in memory between requests, which is sufficient for a developer-local workflow. |
| Frontend | Pure HTML + Tailwind CDN + Fetch API | Zero build step. The dashboard runs in any browser without a Node.js toolchain. |

### Scope boundaries

The tool is designed as a **developer-local pre-commit / pre-deploy check**, not a production runtime monitor. This is a deliberate scope decision, not a limitation:

- It scans files and logs that already exist on disk. It does not intercept live traffic.
- It targets structured PII categories with well-known formats. Free-text PII (e.g. a customer name embedded in a sentence) is out of scope for the current detector set.
- Fix suggestions are heuristic. They cover the four most common leak patterns (direct field log, whole-object log, exception payload, request dict). Novel patterns require manual review.
- Scan history and compliance mapping (Phase 3) are intentionally deferred. The core detect-trace-fix-verify loop is fully functional without them.

### Risk and mitigations

| Risk | Mitigation |
|------|------------|
| False positives in card detection | Luhn checksum validation after regex match. Only valid card numbers are reported. |
| False negatives for obfuscated field names | Source scanner flags any variable named with common PII synonyms. Edge cases are caught by the log scanner which operates on actual output values regardless of variable naming. |
| Fix application corrupts source file | Fixes target a single line number returned by the scanner. The original line is preserved as a comment in the suggested fix output. Version control provides a full safety net. |
| Test data mistaken for real PII | A `.piiignore` allowlist (Phase 3) excludes known fixture paths and synthetic values. In the current phases, demo data is confined to `demo_app/` which can be excluded from production scans. |

---

## Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 1 | ✅ Complete | Scanner MVP — detect PII in logs and source files, display in dashboard |
| Phase 2 | ✅ Complete | AST source tracing, masking, fix suggestion, apply fix, rescan workflow |
| Phase 3 | Planned | Severity engine, confidence scoring, allowlist, scan history, compliance mapping, CLI, export report |
