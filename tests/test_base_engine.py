"""tests/test_base_engine.py — unit tests for DetectionEngine ABC and registry."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from engine.base_engine import (
    DetectionEngine, UnifiedFinding,
    register_engine, get_engine, list_engines, engine_health, run_all_engines,
)
from typing import Any, List


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_finding(title="test finding") -> UnifiedFinding:
    return UnifiedFinding(
        finding_id="abc",
        target="1.2.3.4:80",
        asset_type="service",
        finding_type="test",
        title=title,
        description="desc",
        severity="low",
        confidence=0.9,
        verification_status="verified",
        source_resource="http://1.2.3.4:80/",
    )


# ── UnifiedFinding ────────────────────────────────────────────────────────────

def test_unified_finding_defaults():
    f = _make_finding()
    assert f.finding_status == "new"
    assert f.references == []
    assert f.compliance_frameworks == []
    assert f.rule_id == ""


def test_unified_finding_custom_fields():
    f = UnifiedFinding(
        finding_id="x", target="h:1", asset_type="ip", finding_type="pii",
        title="t", description="d", severity="critical", confidence=1.0,
        verification_status="verified", source_resource="url",
        evidence={"k": "v"}, remediation="fix it",
        references=["https://owasp.org"], compliance_frameworks=["PCI_DSS"],
    )
    assert f.evidence == {"k": "v"}
    assert f.references == ["https://owasp.org"]
    assert f.compliance_frameworks == ["PCI_DSS"]


# ── Registry ──────────────────────────────────────────────────────────────────

def test_register_engine_adds_to_registry():
    @register_engine
    class DummyEngineA(DetectionEngine):
        name = "dummy_engine_a"
        version = "0.1.0"
        def validate_input(self, t: Any) -> bool: return True
        def analyze(self, t: Any) -> List[UnifiedFinding]: return [_make_finding()]

    assert get_engine("dummy_engine_a") is not None
    assert isinstance(get_engine("dummy_engine_a"), DummyEngineA)


def test_register_engine_creates_health_record():
    h = engine_health("dummy_engine_a")
    assert h is not None
    assert h["name"] == "dummy_engine_a"


def test_list_engines_includes_registered():
    engines = list_engines()
    names = [e["name"] for e in engines]
    assert "dummy_engine_a" in names


def test_get_engine_missing_returns_none():
    assert get_engine("nonexistent_engine_xyz") is None


# ── run() harness ─────────────────────────────────────────────────────────────

def test_run_returns_findings():
    eng = get_engine("dummy_engine_a")
    findings = eng.run({})
    assert len(findings) == 1
    assert findings[0].title == "test finding"


def test_run_increments_health():
    eng = get_engine("dummy_engine_a")
    before = engine_health("dummy_engine_a")["runs_total"]
    eng.run({})
    after = engine_health("dummy_engine_a")["runs_total"]
    assert after == before + 1


def test_run_records_error_on_exception():
    @register_engine
    class BrokenEngine(DetectionEngine):
        name = "broken_engine_test"
        version = "0.0.1"
        def validate_input(self, t: Any) -> bool: return True
        def analyze(self, t: Any) -> List[UnifiedFinding]: raise RuntimeError("boom")

    eng = get_engine("broken_engine_test")
    findings = eng.run({})
    assert findings == []
    h = engine_health("broken_engine_test")
    assert h["errors_total"] >= 1
    assert "boom" in h["last_error"]


def test_run_skips_disabled_engine():
    @register_engine
    class DisabledEngine(DetectionEngine):
        name = "disabled_engine_test"
        version = "0.0.1"
        enabled = False
        def validate_input(self, t: Any) -> bool: return True
        def analyze(self, t: Any) -> List[UnifiedFinding]: return [_make_finding()]

    eng = get_engine("disabled_engine_test")
    assert eng.run({}) == []


def test_run_skips_invalid_input():
    @register_engine
    class StrictEngine(DetectionEngine):
        name = "strict_engine_test"
        version = "0.0.1"
        def validate_input(self, t: Any) -> bool: return False
        def analyze(self, t: Any) -> List[UnifiedFinding]: return [_make_finding()]

    eng = get_engine("strict_engine_test")
    assert eng.run({"ip": "1.1.1.1"}) == []


def test_run_all_engines_aggregates():
    findings = run_all_engines({})
    titles = [f.title for f in findings]
    assert "test finding" in titles
