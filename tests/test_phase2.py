"""Phase 2 tests — AST source tracer, masking, fixer, fix endpoint, rescan."""
from __future__ import annotations

import shutil
import tempfile
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.masking import mask_email, mask_ic, mask_card, mask_account_number, mask_phone, mask_value
from app.fixer import suggest_fix
from app.source_tracer import scan_source_files_ast, correlate


# ---------------------------------------------------------------------------
# Masking tests
# ---------------------------------------------------------------------------

class TestMaskEmail:
    def test_standard(self):
        assert mask_email("alice@example.com") == "a****@example.com"

    def test_single_char_local(self):
        result = mask_email("a@b.com")
        assert result.startswith("a")
        assert "@b.com" in result

    def test_longer_local(self):
        result = mask_email("bobby@test.org")
        assert result[0] == "b"
        assert result.endswith("@test.org")
        assert "****" in result

    def test_no_at_sign(self):
        assert mask_email("notanemail") == "****"


class TestMaskIc:
    def test_standard_nric(self):
        result = mask_ic("991231-14-5678")
        assert result[0] == "9"           # first digit preserved
        assert result[-1] == "8"          # last digit preserved
        assert "*" in result

    def test_short_value(self):
        result = mask_ic("12")
        assert result[0] == "1"
        assert result[-1] == "2"


class TestMaskCard:
    def test_16_digit(self):
        assert mask_card("4111111111111111") == "************1111"

    def test_last_four_visible(self):
        result = mask_card("5500005555555559")
        assert result.endswith("5559")
        assert result.startswith("*")

    def test_short_value(self):
        result = mask_card("1234")
        assert result == "1234"  # nothing to mask, all 4 visible


class TestMaskAccountNumber:
    def test_standard(self):
        result = mask_account_number("1234567890")
        assert result.endswith("7890")
        assert result.startswith("******")

    def test_last_four_only(self):
        result = mask_account_number("123456789012")
        assert result.endswith("9012")


class TestMaskPhone:
    def test_plus60(self):
        result = mask_phone("+60123456789")
        assert result.endswith("6789")
        assert "*" in result

    def test_local(self):
        result = mask_phone("0198765432")
        assert result.endswith("5432")


class TestMaskValue:
    def test_dispatch_email(self):
        assert mask_value("EMAIL", "alice@example.com") == mask_email("alice@example.com")

    def test_dispatch_nric(self):
        assert mask_value("NRIC", "991231-14-5678") == mask_ic("991231-14-5678")

    def test_dispatch_card(self):
        assert mask_value("CARD_NUMBER", "4111111111111111") == mask_card("4111111111111111")

    def test_dispatch_account(self):
        assert mask_value("ACCOUNT_NUMBER", "1234567890") == mask_account_number("1234567890")

    def test_dispatch_phone(self):
        assert mask_value("PHONE_NUMBER", "+60123456789") == mask_phone("+60123456789")

    def test_source_leak_passthrough(self):
        snippet = 'logger.info(f"IC: {c.ic_number}")'
        assert mask_value("SOURCE_LEAK", snippet) == snippet

    def test_unknown_type_passthrough(self):
        assert mask_value("UNKNOWN", "somevalue") == "somevalue"


# ---------------------------------------------------------------------------
# AST source tracer tests
# ---------------------------------------------------------------------------

class TestScanSourceFilesAst:
    def test_returns_at_least_four_results(self):
        results = scan_source_files_ast("demo_app/")
        assert len(results) >= 4, f"Expected >= 4, got {len(results)}: {results}"

    def test_direct_field_reference_detected(self):
        results = scan_source_files_ast("demo_app/")
        # Should detect customer.ic_number in customer_service.py
        ic_hits = [r for r in results if "ic_number" in (r.get("pii_fields") or [])]
        assert len(ic_hits) >= 1

    def test_whole_object_logging_detected(self):
        results = scan_source_files_ast("demo_app/")
        whole = [r for r in results if r.get("logs_whole_object")]
        assert len(whole) >= 1

    def test_clean_logging_not_flagged(self):
        """A logger call with no PII reference must not be flagged."""
        tmpdir = tempfile.mkdtemp()
        try:
            clean_py = Path(tmpdir) / "clean.py"
            clean_py.write_text(
                'import logging\nlogger = logging.getLogger(__name__)\n'
                'logger.info("Starting process")\n'
            )
            results = scan_source_files_ast(tmpdir)
            assert results == []
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_results_have_required_keys(self):
        results = scan_source_files_ast("demo_app/")
        required = {"source_file", "source_line", "logger_method", "variables",
                    "pii_fields", "logs_whole_object", "snippet", "pii_type", "severity"}
        for r in results:
            missing = required - r.keys()
            assert not missing, f"Missing keys {missing} in {r}"

    def test_source_line_is_exact_integer(self):
        results = scan_source_files_ast("demo_app/")
        for r in results:
            assert isinstance(r["source_line"], int)
            assert r["source_line"] > 0


# ---------------------------------------------------------------------------
# Correlator tests
# ---------------------------------------------------------------------------

class TestCorrelate:
    def test_log_finding_gets_source_info(self):
        log_findings = [
            {
                "pii_type": "NRIC",
                "value": "991231-14-5678",
                "severity": "HIGH",
                "log_file": "logs/test.log",
                "log_line": 4,
                "source_file": None,
                "source_line": None,
                "snippet": "Verifying identity for IC: 991231-14-5678",
            }
        ]
        source_findings = [
            {
                "source_file": "demo_app/customer_service.py",
                "source_line": 17,
                "logger_method": "info",
                "variables": ["ic_number", "customer"],
                "pii_fields": ["ic_number"],
                "logs_whole_object": False,
                "snippet": 'logger.info(f"Verifying identity for IC: {customer.ic_number}")',
                "pii_type": "SOURCE_LEAK",
                "severity": "HIGH",
                "value": 'logger.info(f"Verifying identity for IC: {customer.ic_number}")',
                "log_file": None,
                "log_line": None,
            }
        ]
        result = correlate(log_findings, source_findings)
        # The log finding should have been enriched with source info
        log_result = next(r for r in result if r["pii_type"] == "NRIC")
        assert log_result["source_file"] == "demo_app/customer_service.py"
        assert log_result["source_line"] == 17

    def test_uncorrelated_finding_unchanged(self):
        log_findings = [
            {
                "pii_type": "EMAIL",
                "value": "alice@example.com",
                "severity": "MEDIUM",
                "log_file": "logs/test.log",
                "log_line": 10,
                "source_file": None,
                "source_line": None,
                "snippet": "User email: alice@example.com",
            }
        ]
        source_findings = [
            {
                "source_file": "demo_app/payment_service.py",
                "source_line": 23,
                "logger_method": "exception",
                "variables": ["payload"],
                "pii_fields": [],
                "logs_whole_object": True,
                "snippet": "logger.exception(error)",
                "pii_type": "SOURCE_LEAK",
                "severity": "HIGH",
                "value": "logger.exception(error)",
                "log_file": None,
                "log_line": None,
            }
        ]
        result = correlate(log_findings, source_findings)
        log_result = next(r for r in result if r["pii_type"] == "EMAIL")
        # Not correlated — source_file should remain None
        assert log_result["source_file"] is None

    def test_high_severity_sorted_first(self):
        findings = [
            {"pii_type": "EMAIL", "severity": "MEDIUM", "value": "x",
             "log_file": None, "log_line": None, "source_file": None, "source_line": None},
            {"pii_type": "NRIC", "severity": "HIGH", "value": "y",
             "log_file": None, "log_line": None, "source_file": None, "source_line": None},
        ]
        result = correlate(findings, [])
        assert result[0]["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# Fixer tests
# ---------------------------------------------------------------------------

class TestSuggestFix:
    def test_pii_field_fix(self):
        match = {
            "source_file": "demo_app/customer_service.py",
            "source_line": 17,
            "snippet": 'logger.info(f"Customer IC: {customer.ic_number}")',
            "pii_fields": ["ic_number"],
            "logs_whole_object": False,
            "variables": ["ic_number", "customer"],
            "logger_method": "info",
        }
        fix = suggest_fix(match)
        assert fix is not None
        assert "mask_ic" in fix
        assert "customer.ic_number" in fix

    def test_whole_object_fix(self):
        match = {
            "source_file": "demo_app/customer_service.py",
            "source_line": 23,
            "snippet": 'logger.info(f"Processing {customer}")',
            "pii_fields": [],
            "logs_whole_object": True,
            "variables": ["customer"],
            "logger_method": "info",
        }
        fix = suggest_fix(match)
        assert fix is not None
        assert "customer.id" in fix
        assert "customer_id" in fix

    def test_no_source_context_returns_none(self):
        match = {
            "source_file": None,
            "source_line": None,
            "snippet": None,
            "pii_fields": [],
            "logs_whole_object": False,
            "variables": [],
        }
        assert suggest_fix(match) is None

    def test_card_field_fix(self):
        match = {
            "source_file": "demo_app/payment_service.py",
            "source_line": 12,
            "snippet": 'logger.debug(f"Card: {customer.card_number}")',
            "pii_fields": ["card_number"],
            "logs_whole_object": False,
            "variables": ["card_number", "customer"],
            "logger_method": "debug",
        }
        fix = suggest_fix(match)
        assert fix is not None
        assert "mask_card" in fix


# ---------------------------------------------------------------------------
# API integration tests (fix + rescan)
# ---------------------------------------------------------------------------

@pytest.fixture()
def demo_app_copy(tmp_path):
    """Copy demo_app into a temp dir so fix tests don't corrupt the real files."""
    src = Path("demo_app")
    dst = tmp_path / "demo_app"
    shutil.copytree(src, dst)
    return str(dst)


@pytest.fixture()
def client():
    from app.main import app
    return TestClient(app)


class TestScanEndpoint:
    def test_scan_returns_results(self, client):
        resp = client.post("/api/scan", json={
            "project_path": "./demo_app",
            "log_path": "./logs/test.log",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert data["total_leaks"] >= 1
        assert len(data["results"]) >= 1

    def test_results_have_masked_value(self, client):
        resp = client.post("/api/scan", json={
            "project_path": "./demo_app",
            "log_path": "./logs/test.log",
        })
        data = resp.json()
        for r in data["results"]:
            assert "masked_value" in r
            assert r["masked_value"] is not None

    def test_results_have_id(self, client):
        resp = client.post("/api/scan", json={
            "project_path": "./demo_app",
            "log_path": "./logs/test.log",
        })
        data = resp.json()
        ids = [r["id"] for r in data["results"]]
        assert len(ids) == len(set(ids)), "IDs must be unique"

    def test_source_findings_have_suggested_fix(self, client):
        resp = client.post("/api/scan", json={
            "project_path": "./demo_app",
            "log_path": "./logs/test.log",
        })
        data = resp.json()
        source_with_fix = [
            r for r in data["results"]
            if r["pii_type"] == "SOURCE_LEAK" and r.get("suggested_fix")
        ]
        assert len(source_with_fix) >= 1


class TestFixEndpoint:
    def test_no_fix_available_when_no_suggested_fix(self, client):
        # First scan to populate state
        scan_resp = client.post("/api/scan", json={
            "project_path": "./demo_app",
            "log_path": "./logs/test.log",
        })
        data = scan_resp.json()
        # Find a finding with no suggested_fix (log-only findings)
        no_fix = next(
            (r for r in data["results"] if not r.get("suggested_fix")), None
        )
        if no_fix is None:
            pytest.skip("All findings have suggested fixes — cannot test no_fix_available path")
        resp = client.post("/api/fix", json={"finding_id": no_fix["id"]})
        assert resp.status_code == 200
        assert resp.json()["status"] == "no_fix_available"

    def test_fix_unknown_id_returns_404(self, client):
        client.post("/api/scan", json={
            "project_path": "./demo_app",
            "log_path": "./logs/test.log",
        })
        resp = client.post("/api/fix", json={"finding_id": "nonexistent-id"})
        assert resp.status_code == 404

    def test_fix_no_scan_returns_400(self):
        # Fresh app instance with no scan state
        from app import main as main_module
        main_module._last_result = None
        from app.main import app
        fresh_client = TestClient(app)
        resp = fresh_client.post("/api/fix", json={"finding_id": "anything"})
        assert resp.status_code == 400


class TestRescanEndpoint:
    def test_rescan_without_prior_scan_returns_400(self):
        from app import main as main_module
        main_module._last_result = None
        main_module._last_request = None
        from app.main import app
        fresh_client = TestClient(app)
        resp = fresh_client.post("/api/rescan")
        assert resp.status_code == 400

    def test_rescan_after_scan_returns_scan_result(self, client):
        client.post("/api/scan", json={
            "project_path": "./demo_app",
            "log_path": "./logs/test.log",
        })
        resp = client.post("/api/rescan")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert "total_leaks" in data
        assert "results" in data
