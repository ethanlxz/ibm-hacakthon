"""Unit and smoke tests for PII detectors and scanners."""
from __future__ import annotations

import pytest

from app.detectors import (
    detect_email,
    detect_ic,
    detect_credit_card,
    detect_account_number,
    detect_phone_number,
)
from app.scanner import scan_log_file, scan_source_files


# ---------------------------------------------------------------------------
# detect_email
# ---------------------------------------------------------------------------

def test_detect_email_hit():
    results = detect_email("Contact us at alice@example.com for support.")
    assert len(results) == 1
    assert results[0]["value"] == "alice@example.com"
    assert results[0]["type"] == "EMAIL"
    assert results[0]["severity"] == "MEDIUM"


def test_detect_email_miss():
    results = detect_email("No email here, just plain text.")
    assert results == []


def test_detect_email_multiple():
    results = detect_email("From: a@b.com To: c@d.org")
    assert len(results) == 2


# ---------------------------------------------------------------------------
# detect_ic
# ---------------------------------------------------------------------------

def test_detect_ic_hit():
    results = detect_ic("Customer IC: 991231-14-5678 verified.")
    assert len(results) == 1
    assert results[0]["value"] == "991231-14-5678"
    assert results[0]["type"] == "NRIC"
    assert results[0]["severity"] == "HIGH"


def test_detect_ic_miss():
    results = detect_ic("No IC number in this string 12345.")
    assert results == []


def test_detect_ic_multiple():
    results = detect_ic("IC1: 870405-10-1234 IC2: 950712-08-4321")
    assert len(results) == 2


# ---------------------------------------------------------------------------
# detect_credit_card
# ---------------------------------------------------------------------------

def test_detect_credit_card_hit_visa():
    results = detect_credit_card("Card: 4111111111111111 processed.")
    assert len(results) == 1
    assert results[0]["value"] == "4111111111111111"
    assert results[0]["type"] == "CARD_NUMBER"
    assert results[0]["severity"] == "HIGH"


def test_detect_credit_card_hit_mastercard():
    results = detect_credit_card("5500005555555559")
    assert len(results) == 1


def test_detect_credit_card_luhn_fail():
    # 4111111111111112 — same length/prefix but fails Luhn
    results = detect_credit_card("4111111111111112")
    assert results == []


def test_detect_credit_card_miss():
    results = detect_credit_card("Order total: $199.99")
    assert results == []


# ---------------------------------------------------------------------------
# detect_account_number
# ---------------------------------------------------------------------------

def test_detect_account_number_hit():
    results = detect_account_number("account_number=1234567890")
    assert len(results) == 1
    assert results[0]["value"] == "1234567890"
    assert results[0]["type"] == "ACCOUNT_NUMBER"
    assert results[0]["severity"] == "HIGH"


def test_detect_account_number_miss():
    results = detect_account_number("Order id: 42 items: 7")
    assert results == []


def test_detect_account_number_no_overlap_with_card():
    # 16-digit Luhn-valid card should NOT appear as an account number
    text = "4111111111111111"
    card_results = detect_credit_card(text)
    acct_results = detect_account_number(text)
    assert len(card_results) == 1
    assert len(acct_results) == 0


# ---------------------------------------------------------------------------
# detect_phone_number
# ---------------------------------------------------------------------------

def test_detect_phone_number_hit_plus60():
    results = detect_phone_number("+60123456789")
    assert len(results) == 1
    assert results[0]["type"] == "PHONE_NUMBER"
    assert results[0]["severity"] == "MEDIUM"


def test_detect_phone_number_hit_local():
    results = detect_phone_number("Call 0198765432 now.")
    assert len(results) == 1


def test_detect_phone_number_miss():
    results = detect_phone_number("Reference number: 00000")
    assert results == []


# ---------------------------------------------------------------------------
# scan_log_file smoke test
# ---------------------------------------------------------------------------

def test_scan_log_file_finds_pii():
    results = scan_log_file("logs/test.log")
    assert len(results) >= 1
    types_found = {r["pii_type"] for r in results}
    # Expect at least email, NRIC, and card number in the log
    assert types_found & {"EMAIL", "NRIC", "CARD_NUMBER"}


# ---------------------------------------------------------------------------
# scan_source_files smoke test
# ---------------------------------------------------------------------------

def test_scan_source_files_finds_leaks():
    results = scan_source_files("demo_app/")
    assert len(results) >= 1
    assert all(r["pii_type"] == "SOURCE_LEAK" for r in results)
    assert all(r["source_file"] is not None for r in results)
    assert all(r["source_line"] is not None for r in results)
