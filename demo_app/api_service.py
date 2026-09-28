"""API service — contains intentional PII leaks for demo purposes."""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def handle_registration_request(request_data: dict) -> dict:
    # LEAK 4 — entire request dict logged at debug level
    logger.debug("Request payload: %s", request_data)
    return {"status": "registered"}
