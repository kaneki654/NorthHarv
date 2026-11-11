"""tests/test_sensitive_file_engine.py — unit tests for SensitiveFileEngine."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import patch
import pytest

from engine.sensitive_file_engine import (
    SensitiveFileEngine, _confirms, _confidence, _safe_snippet,
    _PATHS, SensitivePath,
)

_ENGINE = SensitiveFileEngine()


# ── validate_input ────────────────────────────────────────────────────────────

def test_validate_input_accepts_http_service():
    assert _ENGINE.validate_input({"ip": "1.1.1.1", "port": 80, "http_status": 200})


def test_validate_input_accepts_https_service_name():
    assert _ENGINE.validate_input({"ip": "1.1.1.1", "port": 443, "service_name": "https"})


def test_validate_input_rejects_no_ip():
    assert not _ENGINE.validate_input({"port": 80, "http_status": 200})


def test_validate_input_rejects_non_http_no_status():
    assert not _ENGINE.validate_input({"ip": "1.1.1.1", "port": 22})


# ── _confirms ─────────────────────────────────────────────────────────────────

def test_confirms_true_when_signature_matches():
    sp = SensitivePath("/.env", "env_config", "critical", "desc",
                       body_signatures=["DB_PASSWORD="], min_body_bytes=5)
    assert _confirms(b"DB_PASSWORD=secret123", sp)


def test_confirms_false_when_body_too_short():
    sp = SensitivePath("/.env", "env_config", "critical", "desc",
                       body_signatures=["DB_PASSWORD="], min_body_bytes=100)
    assert not _confirms(b"DB_PASSWORD=x", sp)


def test_confirms_false_when_no_signature_match():
    sp = SensitivePath("/.env", "env_config", "critical", "desc",
                       body_signatures=["SOMETHING_ELSE="], min_body_bytes=5)
    assert not _confirms(b"totally unrelated content here", sp)


def test_confirms_true_with_no_signatures_required():
    sp = SensitivePath("/debug.log", "debug_log", "medium", "desc",
                       body_signatures=[], min_body_bytes=5)
    assert _confirms(b"some log content", sp)


# ── _confidence ───────────────────────────────────────────────────────────────

def test_confidence_increases_with_multiple_hits():
    sp = SensitivePath("/.env", "env_config", "critical", "desc",
                       body_signatures=["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY="])
    body = b"APP_KEY=abc\nDB_PASSWORD=xyz\nSECRET_KEY=qrs"
    conf = _confidence(sp, body)
    assert conf >= 0.90


def test_confidence_critical_base_above_medium():
    sp_crit = SensitivePath("/x", "env_config", "critical", "d", body_signatures=[])
    sp_med  = SensitivePath("/x", "debug_log",  "medium",   "d", body_signatures=[])
    assert _confidence(sp_crit, b"x") > _confidence(sp_med, b"x")


# ── _safe_snippet ─────────────────────────────────────────────────────────────

def test_safe_snippet_redacts_password_lines():
    body = b"DB_HOST=localhost\nDB_PASSWORD=supersecret\nDB_NAME=app"
    snippet = _safe_snippet(body)
    assert "supersecret" not in snippet
    assert "DB_PASSWORD=[REDACTED]" in snippet
    assert "DB_HOST=localhost" in snippet


def test_safe_snippet_keeps_non_credential_lines():
    body = b"CREATE TABLE users (\n  id INT PRIMARY KEY\n);"
    snippet = _safe_snippet(body)
    assert "CREATE TABLE" in snippet


# ── analyze (mocked HTTP) ─────────────────────────────────────────────────────

def _mock_fetch_env(host, port, path, use_tls):
    if path == "/.env":
        return 200, "text/plain", b"APP_KEY=base64abc\nDB_PASSWORD=secret\nSECRET_KEY=xyz"
    return 404, "", b""


def test_analyze_finds_env_file():
    target = {"ip": "192.0.2.1", "port": 80, "http_status": 200}
    with patch("engine.sensitive_file_engine._fetch", side_effect=_mock_fetch_env):
        findings = _ENGINE.analyze(target)
    assert any(f.finding_type == "sensitive_file" for f in findings)
    env_f = next(f for f in findings if f.evidence.get("path") == "/.env")
    assert env_f.severity == "critical"
    assert env_f.confidence > 0.70


def test_analyze_returns_empty_on_all_404():
    target = {"ip": "192.0.2.2", "port": 80, "http_status": 200}
    with patch("engine.sensitive_file_engine._fetch", return_value=(404, "", b"")):
        findings = _ENGINE.analyze(target)
    assert findings == []


def test_analyze_rejects_200_without_signatures():
    target = {"ip": "192.0.2.3", "port": 80, "http_status": 200}
    with patch("engine.sensitive_file_engine._fetch", return_value=(200, "text/html", b"<html>Not found</html>")):
        findings = _ENGINE.analyze(target)
    assert findings == []


def test_analyze_deduplicates_by_path():
    target = {"ip": "192.0.2.4", "port": 80, "http_status": 200}
    body = b"APP_KEY=abc\nDB_PASSWORD=secret"
    with patch("engine.sensitive_file_engine._fetch", return_value=(200, "text/plain", body)):
        findings = _ENGINE.analyze(target)
    paths_seen = [f.evidence["path"] for f in findings]
    assert len(paths_seen) == len(set(paths_seen))


# ── path catalog ──────────────────────────────────────────────────────────────

def test_path_catalog_not_empty():
    assert len(_PATHS) >= 20


def test_path_catalog_all_have_required_fields():
    valid_categories = {
        "env_config", "db_backup", "debug_log",
        "source_map", "archive", "deploy_artifact"
    }
    for sp in _PATHS:
        assert sp.path.startswith("/")
        assert sp.severity in ("critical", "high", "medium", "low")
        assert sp.category in valid_categories
