"""
engine/base_engine.py

DetectionEngine base class and global engine registry for NorthHarv.

Every detection engine sub-classes DetectionEngine and registers itself via
@register_engine.  The registry allows the web layer and CLI to enumerate,
schedule, and health-check engines without importing them individually.

Usage
-----
from engine.base_engine import DetectionEngine, register_engine, get_engine, list_engines

@register_engine
class MyEngine(DetectionEngine):
    name    = "my_engine"
    version = "1.0.0"
    ...
"""
from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Type

log = logging.getLogger("nh.engine_registry")

# ---------------------------------------------------------------------------
# Shared finding model — all engines produce UnifiedFinding instances
# ---------------------------------------------------------------------------

@dataclass
class UnifiedFinding:
    """Canonical finding produced by every DetectionEngine."""
    finding_id:          str
    target:              str            # host:port or URL
    asset_type:          str            # ip, domain, url, service
    finding_type:        str            # credential_exposure, pii, sensitive_file, …
    title:               str
    description:         str
    severity:            str            # critical | high | medium | low | info
    confidence:          float          # 0.0–1.0
    verification_status: str            # verified | probable | unverified | false_positive
    source_resource:     str            # path, URL, or banner location
    evidence:            Dict[str, Any] = field(default_factory=dict)
    detection_engine:    str = ""
    engine_version:      str = ""
    first_observed:      str = ""
    last_observed:       str = ""
    finding_status:      str = "new"    # new | active | changed | resolved | reappeared
    remediation:         str = ""
    references:          List[str] = field(default_factory=list)
    compliance_frameworks: List[str] = field(default_factory=list)
    rule_id:             str = ""
    raw_evidence_key:    str = ""       # opaque ref to separately-stored sensitive value


# ---------------------------------------------------------------------------
# Health record
# ---------------------------------------------------------------------------

@dataclass
class EngineHealth:
    name:           str
    version:        str
    enabled:        bool  = True
    last_run_at:    str   = ""
    last_error:     str   = ""
    runs_total:     int   = 0
    errors_total:   int   = 0
    findings_total: int   = 0
    avg_duration_s: float = 0.0
    _duration_sum:  float = field(default=0.0, repr=False, compare=False)


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class DetectionEngine(ABC):
    """
    Abstract base for all NorthHarv detection engines.

    Sub-class, set class-level name and version, override the abstract
    methods, and decorate with @register_engine.
    """

    name: str        = "base_engine"
    version: str     = "0.0.0"
    description: str = ""
    enabled: bool    = True
    timeout_seconds: float = 30.0

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)

    # -- Required overrides --------------------------------------------------

    @abstractmethod
    def validate_input(self, target: Any) -> bool:
        """Return True when the engine can meaningfully process this target."""

    @abstractmethod
    def analyze(self, target: Any) -> List[UnifiedFinding]:
        """
        Run detection logic against target.
        Must return a list (possibly empty) of UnifiedFinding instances.
        Must never raise — catch and log internally, return [].
        """

    # -- Optional overrides --------------------------------------------------

    def validate_finding(self, candidate: UnifiedFinding) -> bool:
        """Post-analysis validation; default accepts everything."""
        return True

    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """Override for engine-specific confidence logic."""
        return evidence.get("base_confidence", 0.5)

    def generate_finding(self, evidence: Dict[str, Any]) -> Optional[UnifiedFinding]:
        """Convenience wrapper; override when you want declarative rule→finding."""
        return None

    # -- Runtime harness (do not override) -----------------------------------

    def run(self, target: Any) -> List[UnifiedFinding]:
        """Execute the engine safely, record health metrics, return findings."""
        health = _HEALTH.get(self.name)
        if not self.enabled:
            return []
        if not self.validate_input(target):
            return []

        t0 = time.monotonic()
        findings: List[UnifiedFinding] = []
        try:
            raw = self.analyze(target)
            findings = [f for f in (raw or []) if self.validate_finding(f)]
        except Exception as exc:
            err = f"{type(exc).__name__}: {exc}"
            log.error("engine %s error: %s", self.name, err, exc_info=True)
            if health:
                health.last_error = err
                health.errors_total += 1
        finally:
            dur = time.monotonic() - t0
            if health:
                health.runs_total += 1
                health.findings_total += len(findings)
                health.last_run_at = _utcnow()
                health._duration_sum += dur
                health.avg_duration_s = health._duration_sum / max(1, health.runs_total)
        return findings


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_REGISTRY: Dict[str, DetectionEngine] = {}
_HEALTH:   Dict[str, EngineHealth]    = {}


def register_engine(cls: Type[DetectionEngine]) -> Type[DetectionEngine]:
    """
    Class decorator that instantiates and registers an engine.

        @register_engine
        class MyEngine(DetectionEngine):
            name = "my_engine"
    """
    instance = cls()
    _REGISTRY[instance.name] = instance
    _HEALTH[instance.name] = EngineHealth(
        name=instance.name,
        version=instance.version,
        enabled=instance.enabled,
    )
    log.debug("registered engine: %s v%s", instance.name, instance.version)
    return cls


def get_engine(name: str) -> Optional[DetectionEngine]:
    return _REGISTRY.get(name)


def list_engines() -> List[Dict[str, Any]]:
    out = []
    for name, eng in _REGISTRY.items():
        h = _HEALTH.get(name, EngineHealth(name=name, version=eng.version))
        out.append({
            "name":           eng.name,
            "version":        eng.version,
            "description":    eng.description,
            "enabled":        eng.enabled,
            "timeout":        eng.timeout_seconds,
            "runs_total":     h.runs_total,
            "errors_total":   h.errors_total,
            "findings_total": h.findings_total,
            "avg_duration_s": round(h.avg_duration_s, 3),
            "last_run_at":    h.last_run_at,
            "last_error":     h.last_error,
        })
    return out


def engine_health(name: str) -> Optional[Dict[str, Any]]:
    h = _HEALTH.get(name)
    if not h:
        return None
    return {
        "name":           h.name,
        "version":        h.version,
        "enabled":        h.enabled,
        "runs_total":     h.runs_total,
        "errors_total":   h.errors_total,
        "findings_total": h.findings_total,
        "avg_duration_s": round(h.avg_duration_s, 3),
        "last_run_at":    h.last_run_at,
        "last_error":     h.last_error,
    }


def run_all_engines(target: Any) -> List[UnifiedFinding]:
    """Run every registered engine against target, aggregate results."""
    all_findings: List[UnifiedFinding] = []
    for engine in _REGISTRY.values():
        all_findings.extend(engine.run(target))
    return all_findings


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
