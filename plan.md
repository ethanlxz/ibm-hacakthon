# PII Log Leak Detector — Implementation Plan

## Project Goal

Build a lightweight developer security tool that scans:

- Python source code
- Application/test logs
- Logged objects
- Exception messages

for leaked personally identifiable information such as:

- Malaysian NRIC / IC numbers
- Credit/debit card numbers
- Email addresses
- Bank account numbers
- Phone numbers

The system should identify the leak, trace it to the relevant source line, suggest a masking fix, apply the fix, and allow the developer to rerun the scan until the report is clean.

## Technology Stack

Backend:

- Python 3.12+
- FastAPI
- Uvicorn
- Pydantic
- Python `ast`
- Regex
- `pathlib`
- `subprocess`

Frontend:

- Pure HTML
- Tailwind CSS via CDN
- Vanilla JavaScript
- Fetch API

Development:

- Pytest
- Git
- IBM Bob for generating/refactoring fixes

---

# Phase 1 — Build the Scanner MVP

## Goal

Create a working backend capable of scanning a demo codebase and test logs for obvious PII leaks.

## 1. Project Structure

```text
pii-log-detector/
│
├── app/
│   ├── main.py
│   ├── scanner.py
│   ├── detectors.py
│   ├── source_tracer.py
│   ├── fixer.py
│   └── models.py
│
├── demo_app/
│   ├── customer.py
│   ├── customer_service.py
│   ├── payment_service.py
│   └── api_service.py
│
├── logs/
│   └── test.log
│
├── static/
│   ├── index.html
│   └── app.js
│
├── tests/
│   └── test_scanner.py
│
├── requirements.txt
└── README.md
```

## 2. Create Mock Customer Data

Create a simple customer model.

Example fields:

```python
class Customer:
    name: str
    email: str
    ic_number: str
    card_number: str
    account_number: str
```

Seed demo records with fake data.

Example:

```text
Name: Alice Tan
Email: alice@example.com
IC: S1234567D
Card: 4111111111111111
Account: 123456789012
```

All demo information must be synthetic.

## 3. Plant Intentional Leaks

Create 3–4 examples.

### Leak 1 — Direct PII logging

```python
logger.info(f"Customer IC: {customer.ic_number}")
```

### Leak 2 — Entire object

```python
logger.info(f"Processing {customer}")
```

The object's `__repr__()` should expose multiple fields.

### Leak 3 — Exception payload

```python
raise ValueError(f"Invalid payment payload: {payload}")
```

Then:

```python
logger.exception(error)
```

### Leak 4 — Nested request

```python
logger.debug("Request payload: %s", request_data)
```

## 4. Implement PII Detectors

Create:

```text
app/detectors.py
```

Implement functions:

```python
detect_email()
detect_ic()
detect_credit_card()
detect_account_number()
detect_phone_number()
```

Each detector should return:

```json
{
  "type": "EMAIL",
  "value": "alice@example.com",
  "severity": "MEDIUM",
  "start": 15,
  "end": 32
}
```

### Card Validation

Use a Luhn checksum after regex matching.

This reduces false positives.

## 5. Implement Log Scanner

Create:

```python
scan_log_file(path)
```

Responsibilities:

- Open `.log` files
- Read line-by-line
- Run all PII detectors
- Record matching line
- Record log line number
- Record detected value
- Record PII type

Example result:

```json
{
  "pii_type": "CARD_NUMBER",
  "value": "4111111111111111",
  "log_file": "logs/test.log",
  "log_line": 38
}
```

## 6. Implement Source Scanner

Search Python files for dangerous logging patterns.

Look for:

```python
logger.info(...)
logger.debug(...)
logger.warning(...)
logger.error(...)
logger.exception(...)
print(...)
```

Flag cases where logging includes:

- `.email`
- `.ic_number`
- `.card_number`
- `.account_number`
- whole objects
- dictionaries
- request payloads

Initially use text/regex matching.

## 7. FastAPI Backend

Create:

```text
app/main.py
```

Endpoints:

```text
GET  /
POST /api/scan
GET  /api/results
POST /api/fix
POST /api/rescan
```

### POST `/api/scan`

Input:

```json
{
  "project_path": "./demo_app",
  "log_path": "./logs/test.log"
}
```

Output:

```json
{
  "status": "completed",
  "total_leaks": 4,
  "results": []
}
```

## 8. Basic Web Dashboard

Create:

```text
static/index.html
```

Use Tailwind CDN.

Dashboard sections:

### Header

```text
PII Log Leak Detector
Protect sensitive data before it reaches production logs
```

### Scan button

```text
Scan Project
```

### Summary cards

```text
4 Leaks Found
2 High Severity
1 Medium Severity
1 Low Severity
```

### Results table

Columns:

```text
Severity
PII Type
Masked Value
Log File
Source File
Line
Action
```

## Phase 1 Completion Criteria

Phase 1 is complete when:

- FastAPI server runs using Uvicorn
- Demo app produces intentional PII leaks
- Scanner detects at least 3 PII categories
- Web UI displays detected leaks
- Source filenames and approximate lines are displayed

Run using:

```bash
uvicorn app.main:app --reload
```

---

# Phase 2 — Source Tracing and Automated Fixes

## Goal

Turn the scanner from a regex demo into a developer tool capable of identifying the exact code responsible for a leak.

## 1. AST Source Analysis

Replace basic source scanning with Python AST.

Parse each `.py` file using:

```python
ast.parse()
```

Detect calls to:

```python
logger.info
logger.debug
logger.warning
logger.error
logger.exception
```

Capture:

```text
filename
line number
logging method
arguments
variables referenced
```

Example:

```python
logger.info(f"Processing {customer}")
```

AST result:

```json
{
  "file": "customer_service.py",
  "line": 42,
  "logger_method": "info",
  "variables": ["customer"]
}
```

## 2. Source-to-Log Correlation

Attempt to match detected PII values against source logging statements.

Example log:

```text
Processing Customer(email='alice@example.com')
```

Source:

```python
logger.info(f"Processing {customer}")
```

Report:

```text
PII leaked indirectly through Customer.__repr__
```

## 3. Add Masking Functions

Create:

```text
app/masking.py
```

Functions:

```python
mask_email()
mask_ic()
mask_card()
mask_account_number()
mask_phone()
```

Examples:

```text
alice@example.com
a****@example.com

S1234567D
S*****67D

4111111111111111
************1111
```

## 4. Generate Fix Suggestions

Example source:

```python
logger.info(f"Customer IC: {customer.ic_number}")
```

Suggested fix:

```python
logger.info(
    f"Customer IC: {mask_ic(customer.ic_number)}"
)
```

For object logging:

```python
logger.info(f"Processing {customer}")
```

suggest:

```python
logger.info(
    "Processing customer_id=%s",
    customer.id
)
```

## 5. Fix API

Create:

```text
POST /api/fix
```

Input:

```json
{
  "finding_id": "leak-001"
}
```

Output:

```json
{
  "status": "fixed",
  "file": "customer_service.py",
  "line": 42
}
```

For the hackathon version, IBM Bob can perform the actual code rewrite.

## 6. Enhanced UI

Add a leak details panel.

Example:

```text
HIGH — NRIC Leak

Detected:
S*****67D

Found in:
logs/test.log:38

Caused by:
demo_app/customer_service.py:42

Code:
logger.info(f"Processing {customer}")

Recommended fix:
logger.info(
    "Processing customer_id=%s",
    customer.id
)

[Apply Fix]
```

## 7. Rerun Workflow

Add:

```text
Apply Fix
        ↓
Run Tests
        ↓
Generate Logs
        ↓
Rescan
```

Expose:

```text
POST /api/rescan
```

UI status:

```text
Before: 4 leaks
After:  1 leak
```

Eventually:

```text
0 PII leaks detected
```

## Phase 2 Completion Criteria

Phase 2 is complete when:

- Exact source line is identified
- AST identifies unsafe logging statements
- Masking functions exist
- Suggested fixes are generated
- User can apply a fix
- User can rerun scan
- Dashboard updates with remaining leaks

---

# Phase 3 — Hackathon-Ready Security Platform

## Goal

Turn the MVP into a polished tool that looks realistic enough for developer, security, and compliance teams.

## 1. Severity Engine

Assign severity.

### Critical

- Full payment-card number
- Authentication token
- Password

### High

- NRIC
- Passport
- Bank account number

### Medium

- Email
- Phone number

### Low

- Name
- internal customer identifier

Finding format:

```json
{
  "severity": "HIGH",
  "pii_type": "NRIC",
  "confidence": 0.96
}
```

## 2. Confidence Scoring

Add validation rules.

Example:

```text
Regex matched:           +0.5
Expected field name:     +0.2
Known checksum valid:    +0.2
Appears in log context:  +0.1
```

Result:

```text
Confidence: 97%
```

## 3. Allowlist

Support:

```text
.piiignore
```

Example:

```text
tests/fixtures/*
example@example.com
```

Avoid repeatedly reporting known test fixtures.

## 4. Scan History

Store previous scans in memory or lightweight JSON.

Show:

```text
Scan #1 — 8 leaks
Scan #2 — 4 leaks
Scan #3 — 0 leaks
```

Dashboard can show:

```text
Security Improvement

8 ──●
     \
4     ●
       \
0       ●
```

## 5. Compliance Mapping

Map PII categories to relevant security/compliance areas.

Examples:

```text
PDPA
PCI DSS
HIPAA-style healthcare privacy controls
Internal banking security policies
```

Avoid claiming automatic compliance.

Present it as:

```text
Potential compliance exposure
```

## 6. Export Security Report

Endpoint:

```text
GET /api/report
```

Produce JSON initially.

Example:

```json
{
  "scan_id": "scan-003",
  "files_scanned": 18,
  "log_lines_scanned": 1420,
  "leaks_detected": 0,
  "status": "PASS"
}
```

## 7. Final Dashboard Layout

Navigation:

```text
Dashboard
Scan
Findings
History
Settings
```

Dashboard:

```text
┌────────────────────────────────────┐
│ PII Security Score                 │
│                                    │
│              CLEAN                 │
│                                    │
│      0 unresolved PII leaks        │
└────────────────────────────────────┘

Files scanned       Log lines
18                  1,420

Previous leaks      Fixed
4                   4
```

## 8. CLI Interface

Support:

```bash
python pii_scan.py scan .
```

Example:

```text
Scanning project...

✓ 18 Python files scanned
✓ 1,420 log lines scanned

PII Leak Report

HIGH
NRIC detected
logs/test.log:38
Source: customer_service.py:42

HIGH
Credit card detected
logs/test.log:71
Source: payment_service.py:29

2 leaks detected.
```

Clean result:

```text
Scanning project...

✓ 18 Python files scanned
✓ 1,451 log lines scanned

No PII leaks detected.

PASS
```

## 9. Final Demo Flow

### Step 1

Start server.

```bash
uvicorn app.main:app --reload
```

### Step 2

Open:

```text
http://localhost:8000
```

### Step 3

Click:

```text
Scan Project
```

### Step 4

Dashboard shows:

```text
4 PII Leaks Found
```

### Step 5

Select leak.

Show:

```text
Detected NRIC
        ↓
logs/test.log:38
        ↓
customer_service.py:42
        ↓
logger.info(f"Processing {customer}")
```

### Step 6

Click:

```text
Generate Fix
```

IBM Bob modifies the code.

### Step 7

Click:

```text
Rerun Scan
```

### Step 8

Show final state:

```text
✓ 0 PII leaks detected
✓ Security scan passed
```

## Final Success Criteria

The project is ready when the demo clearly communicates:

```text
Detect
  ↓
Trace
  ↓
Explain
  ↓
Fix
  ↓
Verify
```

The key product message:

> Catch sensitive customer data in application logs before those logs ever reach production.