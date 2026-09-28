"""FastAPI application entry point."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.models import PiiMatch, ScanRequest, ScanResult
from app.scanner import scan_log_file, scan_source_files

app = FastAPI(title="PII Log Leak Detector")

# Mount static files for the dashboard
_STATIC_DIR = Path(__file__).parent.parent / "static"
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

# In-memory store for the last scan result
_last_result: ScanResult | None = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
def serve_dashboard():
    return FileResponse(str(_STATIC_DIR / "index.html"))


@app.post("/api/scan", response_model=ScanResult)
def run_scan(request: ScanRequest):
    global _last_result

    log_matches = scan_log_file(request.log_path)
    source_matches = scan_source_files(request.project_path)

    all_matches = log_matches + source_matches
    results = [PiiMatch(**m) for m in all_matches]

    _last_result = ScanResult(
        status="completed",
        total_leaks=len(results),
        results=results,
    )
    return _last_result


@app.get("/api/results", response_model=ScanResult)
def get_results():
    if _last_result is None:
        return ScanResult(status="no_scan", total_leaks=0, results=[])
    return _last_result


@app.post("/api/fix")
def apply_fix():
    # Phase 2 — not yet implemented
    return JSONResponse({"status": "not_implemented"})


@app.post("/api/rescan")
def rescan():
    # Phase 2 — not yet implemented
    return JSONResponse({"status": "not_implemented"})
