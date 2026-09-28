"""PII masking functions.

Each function accepts a raw PII string and returns a redacted version safe
for display in logs, dashboards, and API responses.
"""
from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# Individual masking functions
# ---------------------------------------------------------------------------

def mask_email(value: str) -> str:
    """a****@example.com"""
    if "@" not in value:
        return "****"
    local, _, domain = value.partition("@")
    if len(local) <= 1:
        return f"{local}****@{domain}"
    return f"{local[0]}{'*' * (len(local) - 1)}@{domain}"


def mask_ic(value: str) -> str:
    """991231-14-5678 → 9*****-**-***8"""
    # Strip dashes so we can work on digits, then re-insert separators.
    digits = re.sub(r"[-]", "", value)
    if len(digits) < 2:
        return "****"
    masked_digits = digits[0] + "*" * (len(digits) - 2) + digits[-1]
    # Re-insert dashes at original positions (6-2-4 for Malaysian NRIC)
    if len(masked_digits) == 12:
        return f"{masked_digits[:6]}-{masked_digits[6:8]}-{masked_digits[8:]}"
    return masked_digits


def mask_card(value: str) -> str:
    """4111111111111111 → ************1111"""
    digits = re.sub(r"[\s\-]", "", value)
    visible = digits[-4:] if len(digits) >= 4 else digits
    return "*" * (len(digits) - len(visible)) + visible


def mask_account_number(value: str) -> str:
    """123456789012 → ********9012"""
    digits = re.sub(r"[\s\-]", "", value)
    visible = digits[-4:] if len(digits) >= 4 else digits
    return "*" * (len(digits) - len(visible)) + visible


def mask_phone(value: str) -> str:
    """01X-XXXXXXX → ****XXXX"""
    clean = re.sub(r"[\s\-+]", "", value)
    visible = clean[-4:] if len(clean) >= 4 else clean
    return "*" * (len(clean) - len(visible)) + visible


# ---------------------------------------------------------------------------
# Dispatch function
# ---------------------------------------------------------------------------

_MASK_MAP = {
    "EMAIL": mask_email,
    "NRIC": mask_ic,
    "CARD_NUMBER": mask_card,
    "ACCOUNT_NUMBER": mask_account_number,
    "PHONE_NUMBER": mask_phone,
}


def mask_value(pii_type: str, value: str) -> str:
    """Route *value* to the correct masking function based on *pii_type*.

    Unknown / source-only types return the value unchanged (they don't
    contain raw PII values in the *value* field).
    """
    fn = _MASK_MAP.get(pii_type)
    if fn is None:
        return value
    return fn(value)
