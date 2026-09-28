from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field
from uuid import uuid4


class ScanRequest(BaseModel):
    project_path: str = "./demo_app"
    log_path: str = "./logs/test.log"


class PiiMatch(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    pii_type: str
    value: str
    severity: str  # "HIGH" | "MEDIUM" | "LOW"
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    log_file: Optional[str] = None
    log_line: Optional[int] = None
    snippet: Optional[str] = None
    masked_value: Optional[str] = None
    suggested_fix: Optional[str] = None
    logger_method: Optional[str] = None
    pii_fields: Optional[list[str]] = None
    logs_whole_object: Optional[bool] = None


class ScanResult(BaseModel):
    status: str = "completed"
    total_leaks: int
    results: list[PiiMatch]
