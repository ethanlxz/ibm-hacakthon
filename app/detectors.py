"""PII detector functions. Each accepts a text string and returns a list of match dicts."""
from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _luhn(number: str) -> bool:
    """Return True if *number* (digits only) passes the Luhn checksum."""
    digits = [int(d) for d in number]
    odd_sum = sum(digits[-1::-2])
    even_sum = sum(
        d * 2 - 9 if d * 2 > 9 else d * 2
        for d in digits[-2::-2]
    )
    return (odd_sum + even_sum) % 10 == 0


def _match(pii_type: str, severity: str, m: re.Match) -> dict:
    return {
        "type": pii_type,
        "value": m.group(),
        "severity": severity,
        "start": m.start(),
        "end": m.end(),
    }


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

# Email
_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)


def detect_email(text: str) -> list[dict]:
    return [_match("EMAIL", "MEDIUM", m) for m in _EMAIL_RE.finditer(text)]


# Malaysian NRIC — YYMMDD-PB-###G  (6 digits, dash, 2 digits, dash, 4 digits)
_IC_RE = re.compile(
    r"\b\d{6}-\d{2}-\d{4}\b"
)


def detect_ic(text: str) -> list[dict]:
    return [_match("NRIC", "HIGH", m) for m in _IC_RE.finditer(text)]


# Credit/debit card — 13–19 digits (with optional spaces/dashes), Luhn-validated
_CARD_RE = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3,6})?|"         # Visa
    r"5[1-5][0-9]{14}|"                          # Mastercard
    r"3[47][0-9]{13}|"                           # Amex
    r"6(?:011|5[0-9]{2})[0-9]{12}|"             # Discover
    r"(?:2131|1800|35\d{3})\d{11})\b"           # JCB
)


def detect_credit_card(text: str) -> list[dict]:
    results = []
    for m in _CARD_RE.finditer(text):
        digits = re.sub(r"[\s\-]", "", m.group())
        if _luhn(digits):
            results.append(_match("CARD_NUMBER", "HIGH", m))
    return results


# Bank account number — 10–12 standalone digits NOT already matched as card
# Uses a negative lookbehind/ahead to avoid partial card number overlap.
_ACCOUNT_RE = re.compile(
    r"(?<!\d)\d{10,12}(?!\d)"
)

_CARD_BARE_RE = re.compile(r"\b\d{13,19}\b")


def detect_account_number(text: str) -> list[dict]:
    # Exclude spans already matched by the card pattern
    card_spans = {(m.start(), m.end()) for m in _CARD_BARE_RE.finditer(text)}
    results = []
    for m in _ACCOUNT_RE.finditer(text):
        if (m.start(), m.end()) not in card_spans:
            results.append(_match("ACCOUNT_NUMBER", "HIGH", m))
    return results


# Malaysian phone — +60XXXXXXXXX or 01X-XXXXXXX / 01XXXXXXXXX
_PHONE_RE = re.compile(
    r"(?:\+60|0)1[0-9][\-\s]?\d{3,4}[\-\s]?\d{4}"
)


def detect_phone_number(text: str) -> list[dict]:
    return [_match("PHONE_NUMBER", "MEDIUM", m) for m in _PHONE_RE.finditer(text)]


# ---------------------------------------------------------------------------
# Combined runner (convenience)
# ---------------------------------------------------------------------------

ALL_DETECTORS = [
    detect_email,
    detect_ic,
    detect_credit_card,
    detect_account_number,
    detect_phone_number,
]


def detect_all(text: str) -> list[dict]:
    results = []
    for detector in ALL_DETECTORS:
        results.extend(detector(text))
    return results
