"""
engine/id_detector.py

Identity & Sensitive Data Discovery Engine for NorthHarv.

Scans authorized assets for government IDs, personal information, financial
records, authentication secrets, and confidential documents. All sensitive
values are redacted before they leave this module; no complete credentials,
government IDs, or card numbers are retained or returned anywhere.

Public API
----------
scan_asset(asset, config, dedup_state, log) -> List[Finding]
report_generator(findings, fmt)              -> str (json | csv)
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import math
import re
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

try:
    import pytesseract
    from PIL import Image
    _OCR_AVAILABLE = True
except ImportError:
    _OCR_AVAILABLE = False


# ── Configuration ─────────────────────────────────────────────────────────────
@dataclass
class EngineConfig:
    enable_ocr: bool = False
    enable_entropy_scan: bool = False
    entropy_threshold_bits_per_char: float = 3.8
    min_secret_length: int = 16
    min_confidence_to_report: float = 0.35
    min_confidence_to_available: float = 0.55
    dedupe_window_seconds: int = 300
    redaction_keep_prefix: int = 4
    redaction_keep_suffix: int = 4
    redaction_mask_char: str = "*"
    authorized_asset_roots: List[str] = field(default_factory=list)
    authorized_asset_ids: List[str] = field(default_factory=list)
    allow_all_when_unauthorized: bool = True
    frameworks: Dict[str, str] = field(default_factory=lambda: {
        "PH_DPA":   "Philippine Data Privacy Act of 2012",
        "PCI_DSS":  "PCI DSS v4.0",
        "HIPAA":    "HIPAA",
        "SOC2":     "SOC 2",
        "ISO27001": "ISO/IEC 27001:2022",
    })
    max_asset_size_bytes: int = 50 * 1024 * 1024


# ── Core data structures ──────────────────────────────────────────────────────
@dataclass
class Asset:
    asset_id: str
    uri: str
    content: bytes
    mime_hint: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    finding_id: str
    category: str
    detected_data_type: str
    document_format: str
    source_asset: str
    detection_method: str
    confidence_score: float
    risk_severity: str
    redacted_evidence: str
    discovery_timestamp: str
    validation_status: str
    rule_id: str = ""
    evidence_span_hash: str = ""
    compliance_frameworks: List[str] = field(default_factory=list)


@dataclass
class RawCandidate:
    category: str
    detected_data_type: str
    rule_id: str
    method: str
    span_start: int
    span_end: int
    raw_value: str
    base_confidence: float
    context_keywords: List[str] = field(default_factory=list)
    validator: Optional[str] = None
    requires_context: bool = False
    no_raw_retention: bool = False


# ── Logging ───────────────────────────────────────────────────────────────────
class _SafeLogger:
    def __init__(self, name: str = "nh.identity_engine", level: int = logging.INFO):
        self._log = logging.getLogger(name)
        if not self._log.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter(
                "%(asctime)s %(levelname)s %(name)s :: %(message)s"
            ))
            self._log.addHandler(handler)
        self._log.setLevel(level)

    def info(self, event: str, **fields: Any) -> None:
        self._log.info(json.dumps({"event": event, **fields}, default=str))

    def warn(self, event: str, **fields: Any) -> None:
        self._log.warning(json.dumps({"event": event, **fields}, default=str))

    def error(self, event: str, **fields: Any) -> None:
        self._log.error(json.dumps({"event": event, **fields}, default=str))


# ── Regex rules ───────────────────────────────────────────────────────────────
@dataclass
class RegexRule:
    rule_id: str
    category: str
    data_type: str
    pattern: re.Pattern
    base_confidence: float
    context_keywords: List[str]
    requires_context: bool = False
    validator: Optional[str] = None
    method: str = "regex+context"


_PH_ID_CONTEXT = {
    "philsys":    ["philsys", "philippine identification", "national id", "psn", "phil id"],
    "sss":        ["sss", "social security system", "ss number"],
    "tin":        ["tin", "tax identification", "bir", "taxpayer"],
    "philhealth": ["philhealth"],
    "umid":       ["umid", "unified multi-purpose"],
    "passport":   ["passport", "philippine passport"],
    "license":    ["driver", "drivers license", "driver's license", "lto", "non-pro", "professional license"],
}

_RULES: List[RegexRule] = [
    RegexRule("PH_PHILSYS", "government_id", "PHILIPPINE_NATIONAL_ID",
              re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"), 0.55,
              _PH_ID_CONTEXT["philsys"], requires_context=True),
    RegexRule("PH_SSS", "government_id", "SSS_NUMBER",
              re.compile(r"\b\d{2}[-\s]?\d{7}[-\s]?\d{1}\b"), 0.55,
              _PH_ID_CONTEXT["sss"], requires_context=True),
    RegexRule("PH_TIN", "government_id", "TIN",
              re.compile(r"\b\d{3}[-\s]?\d{3}[-\s]?\d{3}(?:[-\s]?\d{3,5})?\b"), 0.55,
              _PH_ID_CONTEXT["tin"], requires_context=True),
    RegexRule("PH_PHILHEALTH", "government_id", "PHILHEALTH_NUMBER",
              re.compile(r"\b\d{2}[-\s]?\d{9}[-\s]?\d{1}\b"), 0.55,
              _PH_ID_CONTEXT["philhealth"], requires_context=True),
    RegexRule("PH_UMID", "government_id", "UMID",
              re.compile(r"\b\d{4}[-\s]?\d{7}[-\s]?\d{1}\b"), 0.55,
              _PH_ID_CONTEXT["umid"], requires_context=True),
    RegexRule("PH_PASSPORT", "government_id", "PASSPORT_NUMBER",
              re.compile(r"\b[A-Z]{1,2}\d{6,8}[A-Z]?\b"), 0.50,
              _PH_ID_CONTEXT["passport"], requires_context=True),
    RegexRule("PH_LTO_LICENSE", "government_id", "DRIVERS_LICENSE",
              re.compile(r"\b[A-Z0-9]{2}[-\s]?\d{2}[-\s]?\d{6}\b"), 0.50,
              _PH_ID_CONTEXT["license"], requires_context=True),
    RegexRule("PI_EMAIL", "personal_information", "EMAIL_ADDRESS",
              re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), 0.85, []),
    RegexRule("PI_PHONE_PH", "personal_information", "PHONE_NUMBER",
              re.compile(r"(?<!\d)(?:\+63|0)9\d{2}[ -]?\d{3}[ -]?\d{4}(?!\d)"), 0.75,
              ["phone", "mobile", "contact", "cell", "telephone", "tel"]),
    RegexRule("PI_PHONE_PH_LANDLINE", "personal_information", "PHONE_NUMBER",
              re.compile(r"(?<!\d)(?:\+63|0)[2-8]\d{1,2}[ -]?\d{3,4}[ -]?\d{4}(?!\d)"), 0.55,
              ["phone", "landline", "contact", "tel"]),
    RegexRule("PI_DOB", "personal_information", "DATE_OF_BIRTH",
              re.compile(r"\b(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|"
                         r"\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4})\b"),
              0.55, ["dob", "date of birth", "birthdate", "birthday", "born"],
              requires_context=True),
    RegexRule("PI_ADDRESS", "personal_information", "RESIDENTIAL_ADDRESS",
              re.compile(r"\b\d{1,5}\s+(?:[A-Z][A-Za-z0-9.'-]*\s){1,5}"
                         r"(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Blvd\.?|Lane|Ln\.?)\b",
                         re.IGNORECASE),
              0.55, ["address", "residence", "residential"]),
    RegexRule("PI_BARANGAY", "personal_information", "RESIDENTIAL_ADDRESS",
              re.compile(r"\b(?:Barangay|Brgy\.?)\s+[A-Z][A-Za-z0-9.'-]+", re.IGNORECASE),
              0.45, ["address", "barangay", "residence"]),
    RegexRule("FIN_CARD", "financial", "PAYMENT_CARD_NUMBER",
              re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"), 0.55,
              ["card", "visa", "mastercard", "amex", "credit", "debit", "pan"],
              validator="luhn"),
    RegexRule("FIN_BANK_ACCOUNT", "financial", "BANK_ACCOUNT_NUMBER",
              re.compile(r"(?<!\d)\d{8,20}(?!\d)"), 0.40,
              ["account number", "acct", "bank account", "acct no", "account no"]),
    RegexRule("SEC_AWS_ACCESS_KEY", "secret", "AWS_ACCESS_KEY",
              re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0.95, []),
    RegexRule("SEC_GITHUB_TOKEN", "secret", "GITHUB_TOKEN",
              re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), 0.95, []),
    RegexRule("SEC_GOOGLE_API_KEY", "secret", "GOOGLE_API_KEY",
              re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), 0.95, []),
    RegexRule("SEC_SLACK_TOKEN", "secret", "SLACK_TOKEN",
              re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"), 0.90, []),
    RegexRule("SEC_JWT", "secret", "JWT",
              re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"), 0.90, []),
    RegexRule("SEC_BEARER", "secret", "BEARER_TOKEN",
              re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.=]{20,}\b"), 0.80, []),
    RegexRule("SEC_PRIVATE_KEY", "secret", "PRIVATE_KEY",
              re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----"),
              0.99, [], method="regex+structure"),
    RegexRule("SEC_DB_CONN", "secret", "DATABASE_CONNECTION_STRING",
              re.compile(r"\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|mssql|mariadb)"
                         r"://[^\s\"']+"),
              0.92, [], method="regex+structure"),
    RegexRule("SEC_PASSWORD", "secret", "EXPOSED_PASSWORD",
              re.compile(r"(?i)\b(?:password|passwd|pwd|pass)\s*[:=]\s*[\"']?([^\s\"']{6,})[\"']?"),
              0.75, [], method="regex+context"),
]

_SECRET_TYPES = {
    "AWS_ACCESS_KEY", "GITHUB_TOKEN", "GOOGLE_API_KEY", "SLACK_TOKEN",
    "JWT", "BEARER_TOKEN", "PRIVATE_KEY", "DATABASE_CONNECTION_STRING",
    "EXPOSED_PASSWORD",
}

_KEYWORD_RULES: List[RegexRule] = [
    RegexRule("DOC_EMPLOYEE", "confidential_document", "EMPLOYEE_RECORD",
              re.compile(r"(?i)\b(employee (?:record|file|id)|hr record|personnel file)\b"),
              0.45, ["employee", "hr", "personnel"]),
    RegexRule("DOC_CUSTOMER", "confidential_document", "CUSTOMER_RECORD",
              re.compile(r"(?i)\b(customer (?:record|file|data|profile)|client record)\b"),
              0.45, ["customer", "client"]),
    RegexRule("DOC_INTERNAL", "confidential_document", "INTERNAL_COMPANY_DOCUMENT",
              re.compile(r"(?i)\b(internal use only|confidential|do not distribute|"
                         r"proprietary and confidential|for internal use)\b"),
              0.55, []),
    RegexRule("DOC_FINANCIAL_STMT", "financial", "FINANCIAL_STATEMENT",
              re.compile(r"(?i)\b(balance sheet|income statement|cash flow statement|"
                         r"statement of financial position|profit and loss|p&l)\b"),
              0.55, ["financial", "accounting", "audit"]),
    RegexRule("DOC_TAX_RECORD", "financial", "TAX_RECORD",
              re.compile(r"(?i)\b(tax return|withholding tax|form 2316|form 1701|"
                         r"bir form|w-?2|1099|tax record)\b"),
              0.50, ["tax", "bir"]),
    RegexRule("DOC_MEDICAL_ID", "confidential_document", "MEDICAL_RECORD_IDENTIFIER",
              re.compile(r"(?i)\b(medical record(?: number)?|mrn|patient id|"
                         r"diagnosis code|icd-?10)\b"),
              0.55, ["medical", "patient", "diagnosis"]),
]


# ── Helpers ───────────────────────────────────────────────────────────────────
def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_finding_id() -> str:
    return f"fnd_{uuid.uuid4().hex}"


def _hash_value(v: str) -> str:
    return hashlib.sha256(v.encode("utf-8")).hexdigest()[:32]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _luhn_valid(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ── Document classification ───────────────────────────────────────────────────
_PDF_INFO_RE = re.compile(rb"/(Producer|Creator|Author|Title|CreationDate)\s*\(([^)]{0,256})\)")


def document_classifier(content: bytes, mime_hint: Optional[str] = None) -> str:
    """Identify document format from magic bytes, structure, or MIME hint."""
    if not content:
        return "empty"
    head = content[:512]
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith(b"GIF8"):
        return "gif"
    if head.startswith(b"PK\x03\x04"):
        lower = content[:4096].lower()
        if b"word/" in lower:
            return "docx"
        if b"xl/" in lower:
            return "xlsx"
        if b"ppt/" in lower:
            return "pptx"
        return "zip"
    if head.startswith(b"\xd0\xcf\x11\xe0"):
        return "ole"
    stripped = content.lstrip()[:64]
    if stripped.startswith(b"{") or stripped.startswith(b"["):
        try:
            json.loads(content.decode("utf-8", errors="replace")[:65536])
            return "json"
        except Exception:
            pass
    text = content.decode("utf-8", errors="replace")
    first_line = text.split("\n", 1)[0]
    if text.count(",") > 2 and "," in first_line and "\n" in text:
        return "csv"
    if mime_hint:
        m = mime_hint.lower()
        if "json" in m:
            return "json"
        if "csv" in m:
            return "csv"
        if "pdf" in m:
            return "pdf"
        if "text" in m:
            return "txt"
    return "txt"


def document_metadata_extractor(content: bytes, mime_hint: Optional[str] = None) -> Dict[str, Any]:
    meta: Dict[str, Any] = {"mime_hint": mime_hint, "size_bytes": len(content or b"")}
    if content and content.startswith(b"%PDF"):
        for key, val in _PDF_INFO_RE.findall(content[:65536]):
            try:
                meta.setdefault("pdf_info", {})[key.decode("ascii", "ignore")] = \
                    val.decode("latin-1", "ignore")[:128]
            except Exception:
                continue
    return meta


# ── Authorization ─────────────────────────────────────────────────────────────
def _is_authorized_asset(asset: Asset, config: EngineConfig) -> bool:
    if not config.authorized_asset_roots and not config.authorized_asset_ids:
        return config.allow_all_when_unauthorized
    if asset.asset_id in config.authorized_asset_ids:
        return True
    return any(asset.uri.startswith(root) for root in config.authorized_asset_roots)


def asset_discovery(
    sources: Iterable[Asset],
    config: EngineConfig,
    log: Optional[_SafeLogger] = None,
) -> Iterable[Asset]:
    log = log or _SafeLogger()
    for asset in sources:
        if len(asset.content or b"") > config.max_asset_size_bytes:
            log.warn("asset_skipped_size", asset_id=asset.asset_id,
                     size=len(asset.content), limit=config.max_asset_size_bytes)
            continue
        if not _is_authorized_asset(asset, config):
            log.warn("asset_skipped_unauthorized", asset_id=asset.asset_id, uri=asset.uri)
            continue
        yield asset


# ── Detection helpers ─────────────────────────────────────────────────────────
def _has_context(text: str, start: int, end: int, keywords: List[str], window: int = 80) -> bool:
    if not keywords:
        return True
    lo = max(0, start - window)
    hi = min(len(text), end + window)
    surrounding = text[lo:hi].lower()
    return any(k.lower() in surrounding for k in keywords)


def _run_rules(
    text: str,
    rules: Iterable[RegexRule],
    category_filter: Optional[set] = None,
) -> List[RawCandidate]:
    out: List[RawCandidate] = []
    for rule in rules:
        if category_filter and rule.category not in category_filter:
            continue
        for m in rule.pattern.finditer(text):
            raw = m.group(1) if m.lastindex and rule.rule_id == "SEC_PASSWORD" else m.group(0)
            start, end = m.span()
            if rule.requires_context and not _has_context(text, start, end, rule.context_keywords):
                continue
            out.append(RawCandidate(
                category=rule.category,
                detected_data_type=rule.data_type,
                rule_id=rule.rule_id,
                method=rule.method,
                span_start=start,
                span_end=end,
                raw_value=raw,
                base_confidence=rule.base_confidence,
                context_keywords=rule.context_keywords,
                validator=rule.validator,
                requires_context=rule.requires_context,
            ))
    return out


# ── Detectors ─────────────────────────────────────────────────────────────────
def government_id_detector(text: str) -> List[RawCandidate]:
    return _run_rules(text, _RULES, {"government_id"})


_NAME_RE = re.compile(
    r"\b(?:Mr\.|Mrs\.|Ms\.|Dr\.|Engr\.|Atty\.)?\s?"
    r"(?:[A-Z][a-z]{1,20}(?:\s+[A-Z]\.)?(?:\s+[A-Z][a-z]{1,20}){1,3})\b"
)

# Domains that appear in SSH key-exchange algorithm identifiers, not in real emails
_SSH_ALGO_DOMAINS = frozenset({
    "libssh.org", "openssh.com", "ucc.asn.au", "matt.ucc.asn.au",
    "localhost.localdomain", "localhost", "local",
})

# Common words that indicate a regex hit is a UI phrase, not a person's name
_NAME_STOP_WORDS = frozenset({
    "site", "blocked", "host", "name", "content", "version", "server",
    "error", "page", "access", "denied", "forbidden", "default", "redirect",
    "login", "logout", "click", "here", "read", "more", "next", "prev",
    "true", "false", "null", "none", "type", "data", "field", "value",
    "literal", "header", "footer", "section", "menu", "link", "text",
    "found", "failed", "gateway", "maintenance", "router", "season",
    "broadband", "unauthorized", "timeout", "unavailable", "exception",
    "unknown", "invalid", "disabled", "expired", "refused", "reset",
    "online", "offline", "under", "request", "response", "status",
})


# Domains that appear in FTP server banners (developer contact, not user PII)
_FTP_BANNER_EMAIL_DOMAINS = frozenset({
    "filezilla-project.org", "gmx.de",
})

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _is_banner_noise_email(raw: str) -> bool:
    """Returns True if this email-shaped string is banner noise, not a person's email."""
    parts = raw.rsplit("@", 1)
    if len(parts) != 2:
        return False
    local, domain = parts[0], parts[1].lower().rstrip(".")
    # SSH algorithm identifiers
    if domain in _SSH_ALGO_DOMAINS:
        return True
    # FTP server developer emails baked into server banners
    if domain in _FTP_BANNER_EMAIL_DOMAINS:
        return True
    # POP3 / IMAP message IDs: local-part is digits.digits (timestamp)
    if re.match(r"^\d+\.\d+$", local):
        return True
    # UUID-based message IDs: local-part is a UUID
    if _UUID_RE.match(local):
        return True
    # Pure-digit local-parts that are timestamps (e.g. 20261106134751)
    if re.match(r"^\d{10,}$", local):
        return True
    return False


def personal_information_detector(text: str) -> List[RawCandidate]:
    raw_out: List[RawCandidate] = _run_rules(text, _RULES, {"personal_information"})
    # Filter banner noise from emails: SSH algorithm names, FTP developer contacts, message IDs
    out: List[RawCandidate] = [
        c for c in raw_out
        if not (c.detected_data_type == "EMAIL_ADDRESS" and _is_banner_noise_email(c.raw_value))
    ]
    for m in _NAME_RE.finditer(text):
        if "\r" in m.group(0) or "\n" in m.group(0):
            continue
        if not _has_context(text, m.start(), m.end(),
                            ["name", "full name", "customer", "employee",
                             "patient", "contact", "signature", "applicant"], 60):
            continue
        tokens = m.group(0).split()
        if len(tokens) < 2 or len(tokens) > 5:
            continue
        if all(len(t) <= 2 for t in tokens):
            continue
        # Reject if any token is a known stop-word (UI phrase, not a name)
        if any(t.lower() in _NAME_STOP_WORDS for t in tokens):
            continue
        # Require at least one token longer than 3 chars to avoid initials-only matches
        if not any(len(t) > 3 for t in tokens):
            continue
        out.append(RawCandidate(
            category="personal_information",
            detected_data_type="FULL_NAME",
            rule_id="PI_FULL_NAME_HEURISTIC",
            method="heuristic+context",
            span_start=m.start(), span_end=m.end(),
            raw_value=m.group(0),
            base_confidence=0.45,
            context_keywords=["name", "customer", "employee", "patient"],
        ))
    return out


def financial_data_detector(text: str) -> List[RawCandidate]:
    out = _run_rules(text, _RULES, {"financial"})
    out.extend(_run_rules(text, _KEYWORD_RULES, {"financial"}))
    cvv_re = re.compile(r"(?i)\b(?:cvv|cvc|card verification)\b\s*[:=]?\s*\d{3,4}")
    for m in cvv_re.finditer(text):
        out.append(RawCandidate(
            category="financial",
            detected_data_type="CVV_PRESENCE",
            rule_id="FIN_CVV_PRESENCE",
            method="regex+policy",
            span_start=m.start(), span_end=m.end(),
            raw_value="",
            base_confidence=0.99,
            no_raw_retention=True,
        ))
    return out


_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-\.=+/]{16,256}")


def secret_detector(text: str, config: EngineConfig) -> List[RawCandidate]:
    out = _run_rules(text, _RULES, {"secret"})
    if not config.enable_entropy_scan:
        return out
    seen_spans = {(c.span_start, c.span_end) for c in out}
    for m in _TOKEN_RE.finditer(text):
        if (m.start(), m.end()) in seen_spans:
            continue
        token = m.group(0)
        if len(token) < config.min_secret_length:
            continue
        if re.fullmatch(r"[a-f0-9]+", token, re.IGNORECASE):
            continue
        if re.fullmatch(r"[a-z]+", token):
            continue
        entropy = _shannon_entropy(token)
        if entropy < config.entropy_threshold_bits_per_char:
            continue
        out.append(RawCandidate(
            category="secret",
            detected_data_type="HIGH_ENTROPY_STRING",
            rule_id="SEC_ENTROPY",
            method="entropy",
            span_start=m.start(), span_end=m.end(),
            raw_value=token,
            base_confidence=0.40,
            context_keywords=["key", "secret", "token", "password",
                              "credential", "api", "auth"],
        ))
    return out


# ── Scoring & validation ──────────────────────────────────────────────────────
def context_analyzer(cand: RawCandidate, text: str, window: int = 80) -> float:
    if not cand.context_keywords:
        return 0.0
    lo = max(0, cand.span_start - window)
    hi = min(len(text), cand.span_end + window)
    surrounding = text[lo:hi].lower()
    hits = sum(1 for k in cand.context_keywords if k.lower() in surrounding)
    if hits == 0:
        return -0.15 if not cand.requires_context else -0.30
    return min(0.35, 0.15 * hits)


def confidence_scorer(
    base: float, context_delta: float, validator_bonus: float, validator_penalty: float
) -> float:
    score = base + context_delta + validator_bonus - validator_penalty
    return max(0.0, min(1.0, score))


def _card_grouping_valid(raw: str) -> bool:
    """Reject non-card separator patterns like '54-149665781-0 0' (protocol sequence IDs).

    Standard card formats use 4-4-4-4 (16-digit) or 4-6-5 (Amex 15-digit) groupings,
    or no separators at all.  Protocol sequence numbers use irregular groupings.
    """
    # No separators → can't rule out from grouping alone
    if re.fullmatch(r"\d+", raw.strip()):
        return True
    groups = [g for g in re.split(r"[ \-]+", raw.strip()) if g]
    # If only one group survived, separators were trailing/leading noise
    if len(groups) <= 1:
        return True
    lengths = [len(g) for g in groups if g.isdigit()]
    if not lengths:
        return False
    # Accept standard card groupings: 4-4-4-4, 4-4-4-4-3, 4-6-5, or all one group
    valid_groupings = {(4, 4, 4, 4), (4, 4, 4, 4, 3), (4, 6, 5)}
    if tuple(lengths) in valid_groupings:
        return True
    # Reject if any group is suspiciously short (1-2 digits) OR suspiciously long (7+)
    # — these are protocol identifiers, not card numbers
    if any(l <= 2 or l >= 7 for l in lengths):
        return False
    return True


def _validate_candidate(cand: RawCandidate) -> tuple[float, float]:
    if cand.validator == "luhn":
        digits = re.sub(r"[^0-9]", "", cand.raw_value)
        # Payment cards must start with a valid BIN digit (3=Amex, 4=Visa, 5=MC, 6=Discover)
        if not digits or digits[0] not in "3456":
            return (0.0, 0.40)
        # Reject non-standard separator groupings (protocol sequence IDs)
        if not _card_grouping_valid(cand.raw_value):
            return (0.0, 0.40)
        return (0.25, 0.0) if _luhn_valid(cand.raw_value) else (0.0, 0.30)
    if cand.rule_id == "SEC_ENTROPY" and _shannon_entropy(cand.raw_value) >= 4.0:
        return 0.10, 0.0
    return 0.0, 0.0


_SEVERITY_BASE = {
    "PHILIPPINE_NATIONAL_ID": 0.90, "PASSPORT_NUMBER": 0.90,
    "SSS_NUMBER": 0.80,  "TIN": 0.80,  "PHILHEALTH_NUMBER": 0.80,
    "UMID": 0.85,        "DRIVERS_LICENSE": 0.80,
    "PAYMENT_CARD_NUMBER": 0.95, "CVV_PRESENCE": 1.00,
    "BANK_ACCOUNT_NUMBER": 0.85, "FINANCIAL_STATEMENT": 0.70,
    "TAX_RECORD": 0.75,
    "AWS_ACCESS_KEY": 1.00, "GITHUB_TOKEN": 0.98, "GOOGLE_API_KEY": 0.98,
    "SLACK_TOKEN": 0.95,    "JWT": 0.90,           "BEARER_TOKEN": 0.90,
    "PRIVATE_KEY": 1.00,    "DATABASE_CONNECTION_STRING": 1.00,
    "EXPOSED_PASSWORD": 1.00, "HIGH_ENTROPY_STRING": 0.70,
    "EMAIL_ADDRESS": 0.55,   "PHONE_NUMBER": 0.60, "DATE_OF_BIRTH": 0.65,
    "RESIDENTIAL_ADDRESS": 0.65, "FULL_NAME": 0.50,
    "EMPLOYEE_RECORD": 0.70, "CUSTOMER_RECORD": 0.75,
    "INTERNAL_COMPANY_DOCUMENT": 0.60, "MEDICAL_RECORD_IDENTIFIER": 0.90,
}


def risk_calculator(category: str, data_type: str, confidence: float) -> str:
    base = _SEVERITY_BASE.get(data_type, 0.5)
    score = base * (0.5 + 0.5 * confidence)
    if score >= 0.85: return "critical"
    if score >= 0.65: return "high"
    if score >= 0.40: return "medium"
    if score > 0.0:   return "low"
    return "info"


_REDACT_CATEGORIES = {"secret", "financial"}
_REDACT_TYPES = {
    "PAYMENT_CARD_NUMBER", "BANK_ACCOUNT_NUMBER",
    "AWS_ACCESS_KEY", "GITHUB_TOKEN", "GOOGLE_API_KEY", "SLACK_TOKEN",
    "PRIVATE_KEY", "DATABASE_CONNECTION_STRING", "EXPOSED_PASSWORD",
    "BEARER_TOKEN", "JWT",
}


def evidence_redactor(cand: RawCandidate, config: EngineConfig) -> str:
    if cand.no_raw_retention:
        return "[CVV PRESENT — NOT RETAINED]"
    raw = cand.raw_value.strip()
    if not raw:
        return raw
    should_mask = (
        cand.category in _REDACT_CATEGORIES
        or cand.detected_data_type in _REDACT_TYPES
    )
    if should_mask:
        pre = config.redaction_keep_prefix
        suf = config.redaction_keep_suffix
        if len(raw) > pre + suf:
            mask_len = len(raw) - pre - suf
            return raw[:pre] + config.redaction_mask_char * mask_len + raw[-suf:]
    return raw


# ── Deduplication & compliance ────────────────────────────────────────────────
def finding_validator(finding: Finding, config: EngineConfig) -> bool:
    return (finding.confidence_score >= config.min_confidence_to_report
            and finding.validation_status != "rejected")


def finding_deduplicator(
    findings: List[Finding], config: EngineConfig, state: Dict[str, float]
) -> List[Finding]:
    now = time.time()
    for k in [k for k, ts in state.items() if now - ts > config.dedupe_window_seconds]:
        state.pop(k, None)
    seen_in_batch: set = set()
    out: List[Finding] = []
    for f in findings:
        key = (f.category, f.detected_data_type, f.source_asset, f.evidence_span_hash)
        if f.detected_data_type == "CVV_PRESENCE":
            key = (f.category, f.detected_data_type, f.source_asset, "")
        k_str = str(key)
        if k_str in seen_in_batch:
            continue
        seen_in_batch.add(k_str)
        state[k_str] = now
        out.append(f)
    return out


_COMPLIANCE_MAP = {
    "PHILIPPINE_NATIONAL_ID": ["PH_DPA", "ISO27001"],
    "SSS_NUMBER":             ["PH_DPA"],
    "TIN":                    ["PH_DPA"],
    "PHILHEALTH_NUMBER":      ["PH_DPA", "HIPAA"],
    "UMID":                   ["PH_DPA"],
    "PASSPORT_NUMBER":        ["PH_DPA", "ISO27001"],
    "DRIVERS_LICENSE":        ["PH_DPA"],
    "PAYMENT_CARD_NUMBER":    ["PCI_DSS"],
    "CVV_PRESENCE":           ["PCI_DSS"],
    "BANK_ACCOUNT_NUMBER":    ["PCI_DSS", "PH_DPA"],
    "FINANCIAL_STATEMENT":    ["SOC2", "ISO27001"],
    "TAX_RECORD":             ["PH_DPA", "ISO27001"],
    "AWS_ACCESS_KEY":         ["SOC2", "ISO27001"],
    "GITHUB_TOKEN":           ["SOC2", "ISO27001"],
    "GOOGLE_API_KEY":         ["SOC2", "ISO27001"],
    "SLACK_TOKEN":            ["SOC2"],
    "JWT":                    ["SOC2", "ISO27001"],
    "BEARER_TOKEN":           ["SOC2", "ISO27001"],
    "PRIVATE_KEY":            ["SOC2", "ISO27001"],
    "DATABASE_CONNECTION_STRING": ["SOC2", "ISO27001", "PCI_DSS"],
    "EXPOSED_PASSWORD":       ["SOC2", "ISO27001", "PCI_DSS"],
    "HIGH_ENTROPY_STRING":    ["SOC2", "ISO27001"],
    "EMAIL_ADDRESS":          ["PH_DPA"],
    "PHONE_NUMBER":           ["PH_DPA"],
    "DATE_OF_BIRTH":          ["PH_DPA"],
    "RESIDENTIAL_ADDRESS":    ["PH_DPA"],
    "FULL_NAME":              ["PH_DPA"],
    "EMPLOYEE_RECORD":        ["PH_DPA", "ISO27001"],
    "CUSTOMER_RECORD":        ["PH_DPA", "ISO27001"],
    "INTERNAL_COMPANY_DOCUMENT": ["ISO27001"],
    "MEDICAL_RECORD_IDENTIFIER": ["HIPAA", "PH_DPA"],
}


def compliance_mapper(category: str, data_type: str, config: EngineConfig) -> List[str]:
    codes = _COMPLIANCE_MAP.get(data_type, [])
    return [config.frameworks[c] for c in codes if c in config.frameworks]


# ── Structured JSON scan ──────────────────────────────────────────────────────
_SENSITIVE_JSON_KEYS = {
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "access_token", "refresh_token", "private_key",
    "ssn", "tin", "sss", "philhealth", "umid", "passport", "license",
    "card_number", "credit_card", "pan", "account_number",
    "email", "phone", "mobile", "dob", "birthdate", "name", "address",
}
_CVV_KEYS = {"cvv", "cvc", "cvv2", "cvc2", "security_code"}


def _structured_detect_json(obj: Any, text: str) -> List[RawCandidate]:
    out: List[RawCandidate] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                lk = str(k).lower()
                if lk in _CVV_KEYS and v is not None:
                    out.append(RawCandidate(
                        category="financial",
                        detected_data_type="CVV_PRESENCE",
                        rule_id="FIN_CVV_PRESENCE_STRUCTURED",
                        method="structured",
                        span_start=0, span_end=0,
                        raw_value="",
                        base_confidence=0.99,
                        no_raw_retention=True,
                    ))
                    continue
                if lk in _SENSITIVE_JSON_KEYS and v is not None and not isinstance(v, (dict, list)):
                    sv = str(v)
                    if not sv:
                        continue
                    span = max(0, text.find(sv))
                    out.append(RawCandidate(
                        category=_json_key_category(lk),
                        detected_data_type=_json_key_type(lk),
                        rule_id=f"STRUCT_JSON_{lk.upper()}",
                        method="structured",
                        span_start=span, span_end=span + len(sv),
                        raw_value=sv,
                        base_confidence=0.70,
                        context_keywords=[lk],
                    ))
                walk(v)
        elif isinstance(node, list):
            for x in node:
                walk(x)

    walk(obj)
    return out


def _json_key_category(lk: str) -> str:
    if lk in {"password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
              "access_token", "refresh_token", "private_key"}:
        return "secret"
    if lk in {"card_number", "credit_card", "pan", "account_number"}:
        return "financial"
    return "personal_information"


def _json_key_type(lk: str) -> str:
    return {
        "password": "EXPOSED_PASSWORD",   "passwd": "EXPOSED_PASSWORD",
        "pwd": "EXPOSED_PASSWORD",         "secret": "HIGH_ENTROPY_STRING",
        "token": "BEARER_TOKEN",           "api_key": "GOOGLE_API_KEY",
        "apikey": "GOOGLE_API_KEY",        "access_token": "BEARER_TOKEN",
        "refresh_token": "BEARER_TOKEN",   "private_key": "PRIVATE_KEY",
        "card_number": "PAYMENT_CARD_NUMBER", "credit_card": "PAYMENT_CARD_NUMBER",
        "pan": "PAYMENT_CARD_NUMBER",      "account_number": "BANK_ACCOUNT_NUMBER",
        "ssn": "PHILIPPINE_NATIONAL_ID",   "tin": "TIN",
        "sss": "SSS_NUMBER",               "philhealth": "PHILHEALTH_NUMBER",
        "umid": "UMID",                    "passport": "PASSPORT_NUMBER",
        "license": "DRIVERS_LICENSE",      "email": "EMAIL_ADDRESS",
        "phone": "PHONE_NUMBER",           "mobile": "PHONE_NUMBER",
        "dob": "DATE_OF_BIRTH",            "birthdate": "DATE_OF_BIRTH",
        "name": "FULL_NAME",               "address": "RESIDENTIAL_ADDRESS",
    }.get(lk, "UNKNOWN")


# ── Text extraction ───────────────────────────────────────────────────────────
def _extract_text(
    asset: Asset, doc_format: str, config: EngineConfig, log: _SafeLogger
) -> str:
    if doc_format in ("txt", "csv", "json"):
        return asset.content.decode("utf-8", errors="replace")
    if doc_format in ("png", "jpeg", "gif") and config.enable_ocr and _OCR_AVAILABLE:
        try:
            img = Image.open(io.BytesIO(asset.content))
            return pytesseract.image_to_string(img)
        except Exception as exc:
            log.warn("ocr_failed", asset_id=asset.asset_id, error=str(exc))
            return ""
    if doc_format == "pdf":
        try:
            parts = re.findall(rb"\(([^)]{0,500})\)", asset.content[:1_000_000])
            return " ".join(p.decode("latin-1", errors="replace") for p in parts)
        except Exception:
            return ""
    # Fallback: treat as UTF-8 text
    return asset.content.decode("utf-8", errors="replace")


# ── Main orchestration ────────────────────────────────────────────────────────
def scan_asset(
    asset: Asset,
    config: Optional[EngineConfig] = None,
    dedup_state: Optional[Dict] = None,
    log: Optional[_SafeLogger] = None,
) -> List[Finding]:
    """
    Full detection pipeline: classify → extract → detect → score → redact → deduplicate.
    Returns only findings that meet min_confidence_to_report and pass deduplication.
    """
    config = config or EngineConfig()
    log = log or _SafeLogger()
    if dedup_state is None:
        dedup_state = {}

    doc_format = document_classifier(asset.content, asset.mime_hint)
    text = _extract_text(asset, doc_format, config, log)
    if not text:
        return []

    candidates: List[RawCandidate] = []
    candidates.extend(government_id_detector(text))
    candidates.extend(personal_information_detector(text))
    candidates.extend(financial_data_detector(text))
    candidates.extend(secret_detector(text, config))
    candidates.extend(_run_rules(text, _KEYWORD_RULES))

    if doc_format == "json":
        try:
            obj = json.loads(text)
            candidates.extend(_structured_detect_json(obj, text))
        except Exception:
            pass

    findings: List[Finding] = []
    for cand in candidates:
        ctx_delta = context_analyzer(cand, text)
        v_bonus, v_penalty = _validate_candidate(cand)
        confidence = confidence_scorer(cand.base_confidence, ctx_delta, v_bonus, v_penalty)
        if confidence < config.min_confidence_to_report:
            continue

        redacted = evidence_redactor(cand, config)
        severity = risk_calculator(cand.category, cand.detected_data_type, confidence)
        frameworks = compliance_mapper(cand.category, cand.detected_data_type, config)

        span_text = text[cand.span_start:cand.span_end] if cand.span_start < cand.span_end else ""
        span_hash = _hash_value(span_text) if span_text else ""

        if v_bonus > 0:
            validation = "validated"
        elif v_penalty > 0.2:
            validation = "rejected"
        else:
            validation = "unvalidated"

        findings.append(Finding(
            finding_id=_new_finding_id(),
            category=cand.category,
            detected_data_type=cand.detected_data_type,
            document_format=doc_format,
            source_asset=asset.asset_id,
            detection_method=cand.method,
            confidence_score=round(confidence, 3),
            risk_severity=severity,
            redacted_evidence=redacted,
            discovery_timestamp=_utcnow_iso(),
            validation_status=validation,
            rule_id=cand.rule_id,
            evidence_span_hash=span_hash,
            compliance_frameworks=frameworks,
        ))

    return finding_deduplicator(findings, config, dedup_state)


# ── Report export ─────────────────────────────────────────────────────────────
def report_generator(findings: List[Finding], fmt: str = "json") -> str:
    fmt = fmt.lower()
    if fmt == "json":
        return json.dumps([asdict(f) for f in findings], indent=2, default=str)
    if fmt == "csv":
        buf = io.StringIO()
        if not findings:
            return ""
        cols = list(asdict(findings[0]).keys())
        w = csv.DictWriter(buf, fieldnames=cols)
        w.writeheader()
        for f in findings:
            row = asdict(f)
            row["compliance_frameworks"] = ";".join(row["compliance_frameworks"])
            w.writerow(row)
        return buf.getvalue()
    raise ValueError(f"unsupported report format: {fmt}")
