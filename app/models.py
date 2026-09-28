from __future__ import annotations

from typing import Optional
from pydantic import BaseModel


class ScanRequest(BaseModel):
    project_path: str = "./demo_app"
    log_path: str = "./logs/test.log"


class PiiMatch(BaseModel):
    pii_type: str
    value: str
    severity: str  # "HIGH" | "MEDIUM" | "LOW"
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    log_file: Optional[str] = None
    log_line: Optional[int] = None
    snippet: Optional[str] = None


class ScanResult(BaseModel):
    status: str = "completed"
    total_leaks: int
    results: list[PiiMatch]
