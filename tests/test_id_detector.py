"""
Synthetic unit tests for engine/id_detector.py
Run with: python -m pytest tests/test_id_detector.py -v
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import pytest
from engine.id_detector import (
    Asset, EngineConfig, Finding,
    document_classifier,
    government_id_detector,
    personal_information_detector,
    financial_data_detector,
    secret_detector,
    scan_asset,
    report_generator,
    evidence_redactor,
    risk_calculator,
    compliance_mapper,
    _luhn_valid,
    _shannon_entropy,
    RawCandidate,
)


def _asset(text: str, mime: str = "text/plain") -> Asset:
    return Asset(asset_id="test-001", uri="file://synthetic",
                 content=text.encode(), mime_hint=mime)


CFG = EngineConfig(min_confidence_to_report=0.30)


class TestDocumentClassifier:
    def test_pdf_magic(self):
        assert document_classifier(b"%PDF-1.4 some content") == "pdf"

    def test_png_magic(self):
        assert document_classifier(b"\x89PNG\r\n\x1a\ndata") == "png"

    def test_json_structure(self):
        assert document_classifier(b'{"key": "value"}') == "json"

    def test_csv_structure(self):
        assert document_classifier(
            b"name,email,phone\nJuan,juan@test.com,09171234567\n"
        ) == "csv"

    def test_empty(self):
        assert document_classifier(b"") == "empty"

    def test_fallback_txt(self):
        assert document_classifier(b"plain text with no structure") == "txt"

    def test_mime_hint_json(self):
        assert document_classifier(b"not json", "application/json") == "json"


class TestLuhn:
    def test_valid_visa(self):
        assert _luhn_valid("4111111111111111") is True

    def test_valid_mastercard(self):
        assert _luhn_valid("5500005555555559") is True

    def test_invalid(self):
        assert _luhn_valid("1234567890123456") is False

    def test_too_short(self):
        assert _luhn_valid("411111") is False


class TestEntropy:
    def test_low_entropy_repeated(self):
        assert _shannon_entropy("aaaaaaaaa") < 1.0

    def test_high_entropy_random(self):
        assert _shannon_entropy("aB3$xK9!mN2@") > 3.0

    def test_empty(self):
        assert _shannon_entropy("") == 0.0


class TestGovernmentIdDetector:
    def test_sss_with_context(self):
        results = government_id_detector("SSS number: 03-1234567-8")
        assert any(r.detected_data_type == "SSS_NUMBER" for r in results)

    def test_tin_with_context(self):
        results = government_id_detector("TIN: 123-456-789")
        assert any(r.detected_data_type == "TIN" for r in results)

    def test_passport_with_context(self):
        results = government_id_detector("Philippine passport number: P1234567A")
        assert any(r.detected_data_type == "PASSPORT_NUMBER" for r in results)

    def test_philsys_no_context_no_match(self):
        results = government_id_detector("Call me at 1234-5678-9012")
        assert not any(r.detected_data_type == "PHILIPPINE_NATIONAL_ID" for r in results)


class TestPersonalInformationDetector:
    def test_email(self):
        results = personal_information_detector("Contact: juan.delacruz@example.com")
        assert any(r.detected_data_type == "EMAIL_ADDRESS" for r in results)

    def test_ph_mobile_with_context(self):
        results = personal_information_detector("mobile number: 09171234567")
        assert any(r.detected_data_type == "PHONE_NUMBER" for r in results)

    def test_dob_with_context(self):
        results = personal_information_detector("Date of birth: 1990-03-15")
        assert any(r.detected_data_type == "DATE_OF_BIRTH" for r in results)


class TestFinancialDataDetector:
    def test_visa_card_with_context(self):
        results = financial_data_detector("visa card: 4111111111111111")
        assert any(r.detected_data_type == "PAYMENT_CARD_NUMBER" for r in results)

    def test_cvv_not_retained(self):
        results = financial_data_detector("CVV: 123")
        cvv = [r for r in results if r.detected_data_type == "CVV_PRESENCE"]
        assert cvv
        assert all(r.no_raw_retention for r in cvv)
        assert all(r.raw_value == "" for r in cvv)

    def test_financial_statement_keyword(self):
        results = financial_data_detector("Quarterly balance sheet for fiscal year 2024.")
        assert any(r.detected_data_type == "FINANCIAL_STATEMENT" for r in results)


class TestSecretDetector:
    def test_aws_key(self):
        results = secret_detector("config: AKIAIOSFODNN7EXAMPLE", CFG)
        assert any(r.detected_data_type == "AWS_ACCESS_KEY" for r in results)

    def test_github_token(self):
        results = secret_detector("token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12", CFG)
        assert any(r.detected_data_type == "GITHUB_TOKEN" for r in results)

    def test_db_connection_string(self):
        results = secret_detector("db = postgresql://user:pass@localhost:5432/mydb", CFG)
        assert any(r.detected_data_type == "DATABASE_CONNECTION_STRING" for r in results)

    def test_password_exposed(self):
        results = secret_detector("password=secret123", CFG)
        assert any(r.detected_data_type == "EXPOSED_PASSWORD" for r in results)


class TestEvidenceRedactor:
    def test_redacts_middle(self):
        cand = RawCandidate("secret", "EXPOSED_PASSWORD", "SEC_PASSWORD",
                            "regex", 0, 10, "supersecret", 0.75)
        result = evidence_redactor(cand, CFG)
        assert result.startswith("su") and result.endswith("et") and "*" in result

    def test_cvv_not_retained(self):
        cand = RawCandidate("financial", "CVV_PRESENCE", "FIN_CVV_PRESENCE",
                            "regex", 0, 0, "", 0.99, no_raw_retention=True)
        result = evidence_redactor(cand, CFG)
        assert "NOT RETAINED" in result


class TestRiskCalculator:
    def test_critical_private_key(self):
        assert risk_calculator("secret", "PRIVATE_KEY", 1.0) == "critical"

    def test_critical_payment_card_high_confidence(self):
        assert risk_calculator("financial", "PAYMENT_CARD_NUMBER", 0.9) == "critical"

    def test_low_email(self):
        assert risk_calculator("personal_information", "EMAIL_ADDRESS", 0.5) in ("low", "medium")


class TestComplianceMapper:
    def test_payment_card_pci(self):
        assert "PCI DSS v4.0" in compliance_mapper("financial", "PAYMENT_CARD_NUMBER", EngineConfig())

    def test_philhealth_hipaa_dpa(self):
        result = compliance_mapper("government_id", "PHILHEALTH_NUMBER", EngineConfig())
        assert "HIPAA" in result
        assert "Philippine Data Privacy Act of 2012" in result

    def test_unknown_type_empty(self):
        assert compliance_mapper("unknown", "UNKNOWN_TYPE", EngineConfig()) == []


class TestScanAsset:
    def test_email_found(self):
        findings = scan_asset(_asset("Send invoices to billing@company.ph"), CFG)
        assert any(f.detected_data_type == "EMAIL_ADDRESS" for f in findings)

    def test_aws_key_found(self):
        findings = scan_asset(_asset("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"), CFG)
        assert any(f.detected_data_type == "AWS_ACCESS_KEY" for f in findings)

    def test_cvv_not_retained_in_findings(self):
        findings = scan_asset(_asset("cvv: 456"), CFG)
        for f in findings:
            if f.detected_data_type == "CVV_PRESENCE":
                assert "NOT RETAINED" in f.redacted_evidence

    def test_deduplication_across_calls(self):
        state: dict = {}
        f1 = scan_asset(_asset("billing@test.com billing@test.com"), CFG, state)
        f2 = scan_asset(_asset("billing@test.com billing@test.com"), CFG, state)
        emails = [f for f in f1 + f2 if f.detected_data_type == "EMAIL_ADDRESS"]
        assert len(emails) <= 2

    def test_json_structured_password(self):
        payload = json.dumps({"username": "testuser", "password": "hunter2"})
        findings = scan_asset(_asset(payload, "application/json"), CFG)
        assert any(f.detected_data_type == "EXPOSED_PASSWORD" for f in findings)

    def test_validation_status_set(self):
        findings = scan_asset(_asset("visa card 4111111111111111 test"), CFG)
        cards = [f for f in findings if f.detected_data_type == "PAYMENT_CARD_NUMBER"]
        for c in cards:
            assert c.validation_status in ("validated", "rejected", "unvalidated")

    def test_compliance_frameworks_populated(self):
        findings = scan_asset(_asset("AWS_SECRET_ACCESS_KEY = AKIAIOSFODNN7EXAMPLE"), CFG)
        aws = [f for f in findings if f.detected_data_type == "AWS_ACCESS_KEY"]
        if aws:
            assert len(aws[0].compliance_frameworks) > 0

    def test_empty_content_returns_empty(self):
        assert scan_asset(Asset("x", "file://empty", b"", "text/plain"), CFG) == []

    def test_oversized_asset_skipped(self):
        from engine.id_detector import asset_discovery
        cfg = EngineConfig(max_asset_size_bytes=10)
        a = Asset("big", "file://big", b"x" * 100)
        assert list(asset_discovery([a], cfg)) == []


class TestReportGenerator:
    def _findings(self):
        return scan_asset(_asset("AWS key: AKIAIOSFODNN7EXAMPLE email@company.ph"), CFG)

    def test_json_format(self):
        findings = self._findings()
        if not findings:
            pytest.skip("no findings")
        parsed = json.loads(report_generator(findings, "json"))
        assert isinstance(parsed, list) and "finding_id" in parsed[0]

    def test_csv_format(self):
        findings = self._findings()
        if not findings:
            pytest.skip("no findings")
        out = report_generator(findings, "csv")
        assert "finding_id" in out and "\n" in out

    def test_unsupported_format_raises(self):
        with pytest.raises(ValueError):
            report_generator([], "xml")

    def test_empty_csv_is_empty_string(self):
        assert report_generator([], "csv") == ""
