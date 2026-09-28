"""FastAPI application entry point."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.models import PiiMatch, ScanRequest, ScanResult
from app.scanner import scan_log_file
from app.source_tracer import scan_source_files_ast, correlate
from app.masking import mask_value
from app.fixer import suggest_fix

app = FastAPI(title="PII Log Leak Detector")

# Mount static files for the dashboard
_STATIC_DIR = Path(__file__).parent.parent / "static"
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

# In-memory store for the last scan result and request
_last_result: ScanResult | None = None
_last_request: ScanRequest | None = None


# ---------------------------------------------------------------------------
# Internal pipeline helper
# ---------------------------------------------------------------------------

def _run_pipeline(request: ScanRequest) -> ScanResult:
    """Run the full scan pipeline and return a ScanResult."""
    log_matches = scan_log_file(request.log_path)
    source_matches = scan_source_files_ast(request.project_path)

    # Correlate log findings with their source origins
    all_matches = correlate(log_matches, source_matches)

    results: list[PiiMatch] = []
    for m in all_matches:
        match_dict = dict(m)
        # Apply masking
        match_dict["masked_value"] = mask_value(
            match_dict.get("pii_type", ""), match_dict.get("value", "")
        )
        # Generate fix suggestion
        match_dict["suggested_fix"] = suggest_fix(match_dict)
        results.append(PiiMatch(**match_dict))

    return ScanResult(
        status="completed",
        total_leaks=len(results),
        results=results,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
def serve_dashboard():
    return FileResponse(str(_STATIC_DIR / "index.html"))


@app.post("/api/scan", response_model=ScanResult)
def run_scan(request: ScanRequest):
    global _last_result, _last_request

    _last_request = request
    _last_result = _run_pipeline(request)
    return _last_result


@app.get("/api/results", response_model=ScanResult)
def get_results():
    if _last_result is None:
        return ScanResult(status="no_scan", total_leaks=0, results=[])
    return _last_result


class FixRequest(BaseModel):
    finding_id: str


@app.post("/api/fix")
def apply_fix(body: FixRequest):
    global _last_result

    if _last_result is None:
        raise HTTPException(status_code=400, detail="No scan results available.")

    # Look up the finding by its UUID
    finding: Optional[PiiMatch] = None
    for r in _last_result.results:
        if r.id == body.finding_id:
            finding = r
            break

    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")

    if not finding.suggested_fix:
        return JSONResponse({"status": "no_fix_available"})

    if not finding.source_file or finding.source_line is None:
        return JSONResponse({"status": "no_fix_available"})

    # Read the source file and replace the flagged line
    source_path = Path(finding.source_file)
    if not source_path.exists():
        raise HTTPException(status_code=404, detail=f"Source file not found: {finding.source_file}")

    lines = source_path.read_text(encoding="utf-8").splitlines(keepends=True)
    line_idx = finding.source_line - 1

    if line_idx < 0 or line_idx >= len(lines):
        raise HTTPException(status_code=400, detail="Line number out of range.")

    # Preserve indentation from the original line
    original = lines[line_idx]
    indent = len(original) - len(original.lstrip())
    new_line = " " * indent + finding.suggested_fix.strip() + "\n"
    lines[line_idx] = new_line

    source_path.write_text("".join(lines), encoding="utf-8")

    return JSONResponse({
        "status": "fixed",
        "file": str(finding.source_file),
        "line": finding.source_line,
    })


@app.post("/api/rescan", response_model=ScanResult)
def rescan():
    global _last_result, _last_request

    if _last_request is None:
        raise HTTPException(status_code=400, detail="No previous scan to rescan.")

    _last_result = _run_pipeline(_last_request)
    return _last_result
