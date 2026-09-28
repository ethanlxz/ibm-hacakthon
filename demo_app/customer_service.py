"""Customer service — contains intentional PII leaks for demo purposes."""
from __future__ import annotations

import logging

from demo_app.customer import Customer, DEMO_CUSTOMERS

logger = logging.getLogger(__name__)


def get_customer(customer_id: int) -> Customer:
    return DEMO_CUSTOMERS[customer_id % len(DEMO_CUSTOMERS)]


def verify_identity(customer: Customer) -> bool:
    # LEAK 1 — direct PII field logged
    logger.info(f"Verifying identity for IC: {customer.ic_number}")
    return True


def process_customer(customer: Customer) -> dict:
    # LEAK 2 — entire object logged (exposes all fields via __repr__)
    logger.info(f"Processing {customer}")
    return {"status": "ok", "customer_id": id(customer)}
