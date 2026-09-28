"""Payment service — contains intentional PII leaks for demo purposes."""
from __future__ import annotations

import logging

from demo_app.customer import Customer

logger = logging.getLogger(__name__)


def process_payment(customer: Customer, amount: float) -> dict:
    payload = {
        "card_number": customer.card_number,
        "account_number": customer.account_number,
        "amount": amount,
    }
    try:
        if amount <= 0:
            # LEAK 3 — exception message contains raw payment payload
            raise ValueError(f"Invalid payment payload: {payload}")
        return {"status": "approved", "amount": amount}
    except ValueError as error:
        logger.exception(error)
        raise
