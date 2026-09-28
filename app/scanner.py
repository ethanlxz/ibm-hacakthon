"""Log file scanner and Python source code scanner."""
from __future__ import annotations

import re
from pathlib import Path

from app.detectors import detect_all

# ---------------------------------------------------------------------------
# Dangerous logging patterns for source scanner
# ---------------------------------------------------------------------------

_LOG_CALL_RE = re.compile(
    r"(logger\.(info|debug|warning|error|exception)|print)\s*\("
)

_PII_FIELD_RE = re.compile(
    r"\.(ic_number|card_number|email|account_number|phone)"
    r"|request[_ ]?(?:data|payload)|payload|request\b"
)

_WHOLE_OBJECT_RE = re.compile(
    r"\{[a-zA-Z_][a-zA-Z0-9_]*\}"   # bare f-string variable like {customer}
)


# ---------------------------------------------------------------------------
# Log Scanner
# ---------------------------------------------------------------------------

def scan_log_file(path: str) -> list[dict]:
    """Scan *path* line-by-line and return one result dict per PII match."""
    results = []
    log_path = Path(path)
    with log_path.open(encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, start=1):
            for match in detect_all(line):
                results.append(
                    {
                        "pii_type": match["type"],
                        "value": match["value"],
                        "severity": match["severity"],
                        "log_file": str(log_path),
                        "log_line": line_no,
                        "source_file": None,
                        "source_line": None,
                        "snippet": line.rstrip(),
                    }
                )
    return results


# ---------------------------------------------------------------------------
# Source Scanner
# ---------------------------------------------------------------------------

def scan_source_files(path: str) -> list[dict]:
    """Scan Python files under *path* for dangerous logging patterns."""
    results = []
    root = Path(path)
    for py_file in sorted(root.rglob("*.py")):
        with py_file.open(encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not _LOG_CALL_RE.search(stripped):
                continue
            # Flag if line references a PII field, a whole-object f-string,
            # or a request/payload variable
            if _PII_FIELD_RE.search(stripped) or _WHOLE_OBJECT_RE.search(stripped):
                results.append(
                    {
                        "pii_type": "SOURCE_LEAK",
                        "value": stripped,
                        "severity": "HIGH",
                        "source_file": str(py_file),
                        "source_line": line_no,
                        "log_file": None,
                        "log_line": None,
                        "snippet": stripped,
                    }
                )
    return results
