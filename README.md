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
            │  Source Scanner │  │   Log Scanner     │
            │  (scanner.py)   │  │   (scanner.py)    │
            └──────────┬──────┘  └────────┬──────────┘
                       │                  │
            Walks .py files        Reads .log line
            with pathlib.rglob     by line
                       │                  │
            Flags logger.*() /     Runs all 5 PII
            print() calls that     detectors on
            reference PII fields   each line
            or whole objects       │
                       │          │
                       └────┬─────┘
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
                   │  PiiMatch list  │
                   │  (models.py)    │
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
                   └─────────────────┘
```

### Two scan modes

**Log scanner** — opens `.log` files and runs all five PII detectors against every line. Returns the PII type, masked value, file path, and exact line number of each hit.

**Source scanner** — walks all `.py` files under the target directory and flags any `logger.*()` or `print()` call whose argument references a PII field name (`.ic_number`, `.card_number`, `.email`, `.account_number`, `.phone`), a whole-object f-string interpolation (`{customer}`), or a `request`/`payload` variable. This catches leaks at the source before they ever produce output.

Both scan modes produce `PiiMatch` records that share the same Pydantic model, so the API response and dashboard treat log-origin and source-origin findings uniformly.

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

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Serves the web dashboard |
| `POST` | `/api/scan` | Runs both scanners, returns `ScanResult` |
| `GET` | `/api/results` | Returns the most recent scan result |
| `POST` | `/api/fix` | Apply a suggested fix to the source file |
| `POST` | `/api/rescan` | Re-run the full scan pipeline after fixes |

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

## Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 1 | ✅ Complete | Scanner MVP — detect PII in logs and source files, display in dashboard |
| Phase 2 | ✅ Complete | AST source tracing, masking, fix suggestion, apply fix, rescan workflow |
| Phase 3 | Planned | Severity engine, confidence scoring, allowlist, scan history, compliance mapping, CLI, export report |
