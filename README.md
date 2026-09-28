# BobGuard — PII Log Leak Detector

> **Built with IBM Bob** · Python 3.12 · FastAPI · Tailwind CSS

BobGuard is a developer security tool that catches personally identifiable information (PII) leaking through application logs and source code **before those logs ever reach production**. It was scaffolded, implemented, and refined entirely through IBM Bob — from initial plan generation through code writing, test authoring, and iterative fixing — making it a working demonstration of AI-assisted secure software development.

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
│   ├── main.py          # FastAPI application — 5 endpoints
│   ├── scanner.py       # scan_log_file() + scan_source_files()
│   ├── detectors.py     # 5 PII detector functions + Luhn helper
│   └── models.py        # ScanRequest, PiiMatch, ScanResult (Pydantic)
│
├── demo_app/            # Synthetic codebase with intentional leaks
│   ├── customer.py      # Customer dataclass + DEMO_CUSTOMERS seed data
│   ├── customer_service.py   # Leak 1: direct IC log, Leak 2: whole object
│   ├── payment_service.py    # Leak 3: exception with card payload
│   └── api_service.py        # Leak 4: debug log of request dict
│
├── logs/
│   └── test.log         # 43-line pre-generated log with embedded PII
│
├── static/
│   ├── index.html       # Tailwind CSS dashboard
│   └── app.js           # scanProject(), masking helper, severity badges
│
├── tests/
│   └── test_scanner.py  # 18 unit + smoke tests
│
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
| `POST` | `/api/fix` | *(Phase 2)* Apply a suggested fix |
| `POST` | `/api/rescan` | *(Phase 2)* Re-run scan after fixes |

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
      "pii_type": "NRIC",
      "value": "991231-14-5678",
      "severity": "HIGH",
      "log_file": "logs/test.log",
      "log_line": 4,
      "source_file": null,
      "source_line": null
    },
    {
      "pii_type": "SOURCE_LEAK",
      "value": "logger.info(f\"Verifying identity for IC: {customer.ic_number}\")",
      "severity": "HIGH",
      "source_file": "demo_app/customer_service.py",
      "source_line": 17,
      "log_file": null,
      "log_line": null
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

## The IBM Bob Connection

Every file in this project was written by IBM Bob based on a structured plan (`phase1-plan.md`) that Bob also generated. The workflow was:

1. `plan.md` described the full three-phase project vision.
2. Bob read `plan.md` and produced `phase1-plan.md` — a sub-task breakdown with intent, expected outcomes, and acceptance criteria for each step.
3. Bob executed each sub-task in order: scaffold → models → demo app → detectors → scanners → API → dashboard.
4. Bob ran `pytest` and verified 18/18 passing before declaring Phase 1 complete.

This demonstrates the **Detect → Trace → Explain → Fix → Verify** loop that BobGuard itself implements for PII leaks — applied to the development process itself.

---

## Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 1 | ✅ Complete | Scanner MVP — detect and display |
| Phase 2 | Planned | AST source tracing, masking functions, fix application, rescan workflow |
| Phase 3 | Planned | Severity engine, confidence scoring, allowlist, scan history, compliance mapping, CLI, export report |
