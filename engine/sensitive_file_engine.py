"""
engine/sensitive_file_engine.py

Sensitive File Discovery Engine for NorthHarv.

Probes authorized HTTP/HTTPS services for accidentally exposed sensitive
files: environment configs, database backups, source maps, deployment
artifacts, debug logs, and configuration exports.

Detection is two-stage:
  1. HTTP GET request to known sensitive paths.
  2. Content analysis — body must contain known signatures; plain 200 OK
     on a custom 404 page is rejected.

The engine never:
  - Reads more than MAX_RESPONSE_BYTES from any resource.
  - Stores raw credentials found in config files (redacted in snippet).
  - Follows redirects outside the authorized origin.
  - Performs authentication or POST requests.
"""
from __future__ import annotations

import hashlib
import http.client
import re
import ssl
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from engine.base_engine import DetectionEngine, UnifiedFinding, register_engine

MAX_RESPONSE_BYTES = 64 * 1024
CONNECT_TIMEOUT    = 5.0
READ_TIMEOUT       = 8.0
_VERSION           = "1.0.0"


# ---------------------------------------------------------------------------
# Path catalog
# ---------------------------------------------------------------------------

@dataclass
class SensitivePath:
    path:               str
    category:           str    # env_config | db_backup | debug_log | source_map | archive | deploy_artifact
    severity:           str    # critical | high | medium | low
    description:        str
    body_signatures:    List[str] = field(default_factory=list)
    content_type_hints: List[str] = field(default_factory=list)
    min_body_bytes:     int = 32
    remediation:        str = ""
    references:         List[str] = field(default_factory=list)


_PATHS: List[SensitivePath] = [
    # ── Environment configs ──────────────────────────────────────────────
    SensitivePath("/.env", "env_config", "critical",
        "Environment configuration file exposed",
        ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY=", "API_KEY=",
         "DATABASE_URL=", "AWS_SECRET", "MAIL_PASSWORD=", "JWT_SECRET", "REDIS_PASSWORD"],
        ["text/plain", "application/octet"], 10,
        "Move .env outside the web root and restrict file access.",
        ["https://owasp.org/www-project-top-ten/"]),
    SensitivePath("/.env.local",      "env_config", "critical",
        "Local environment config exposed",
        ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY=", "API_KEY="], [], 10,
        "Move .env.local outside the web root."),
    SensitivePath("/.env.production", "env_config", "critical",
        "Production environment config exposed",
        ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY="], [], 10,
        "Move .env.production outside the web root."),
    SensitivePath("/.env.staging",    "env_config", "high",
        "Staging environment config exposed",
        ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY="], [], 10,
        "Move .env.staging outside the web root."),
    SensitivePath("/.env.backup",     "env_config", "critical",
        "Environment backup file exposed",
        ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY="], [], 10),
    SensitivePath("/config.php",      "env_config", "high",
        "PHP configuration file exposed",
        ["define(", "$db_", "password", "DB_HOST"], ["text/plain", "text/html"], 20,
        "Restrict access to config.php via web server rules."),
    SensitivePath("/config.yml",      "env_config", "high",
        "YAML configuration file exposed",
        ["password:", "secret:", "key:", "database:"],
        ["text/plain", "application/x-yaml", "text/yaml"], 10),
    SensitivePath("/config.yaml",     "env_config", "high",
        "YAML configuration file exposed",
        ["password:", "secret:", "key:", "database:"], [], 10),
    SensitivePath("/config.json",     "env_config", "high",
        "JSON configuration file exposed",
        ['"password"', '"secret"', '"key"', '"database"', '"credentials"'],
        ["application/json"], 10),
    SensitivePath("/application.properties", "env_config", "high",
        "Java application properties exposed",
        ["datasource.password=", "spring.security", "aws.secretKey"], [], 10),
    SensitivePath("/wp-config.php",   "env_config", "critical",
        "WordPress configuration file exposed",
        ["DB_PASSWORD", "DB_HOST", "table_prefix", "AUTH_KEY"], [], 20,
        "Move wp-config.php one level above the web root."),
    SensitivePath("/settings.py",     "env_config", "high",
        "Django settings file exposed",
        ["SECRET_KEY", "DATABASES", "PASSWORD", "ALLOWED_HOSTS"], [], 20),
    SensitivePath("/.htpasswd",       "env_config", "high",
        "HTTP authentication credentials file exposed",
        [":$apr1$", ":$2y$", ":{SHA}", ":{plain}"], [], 10,
        "Move .htpasswd outside the document root."),

    # ── Database backups / dumps ─────────────────────────────────────────
    SensitivePath("/backup.sql",      "db_backup", "critical",
        "SQL database dump exposed",
        ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "-- MySQL"],
        ["text/plain", "application/sql", "application/octet"], 20,
        "Remove database backups from the web root."),
    SensitivePath("/database.sql",    "db_backup", "critical",
        "SQL database dump exposed",
        ["CREATE TABLE", "INSERT INTO", "DROP TABLE"], [], 20),
    SensitivePath("/dump.sql",        "db_backup", "critical",
        "SQL database dump exposed",
        ["CREATE TABLE", "INSERT INTO"], [], 20),
    SensitivePath("/data.sql",        "db_backup", "critical",
        "SQL database dump exposed",
        ["CREATE TABLE", "INSERT INTO"], [], 20),
    SensitivePath("/db.sqlite",       "db_backup", "critical",
        "SQLite database file exposed",
        ["SQLite format 3"],
        ["application/x-sqlite3", "application/octet"], 16),
    SensitivePath("/db.sqlite3",      "db_backup", "critical",
        "SQLite database file exposed",
        ["SQLite format 3"], [], 16),
    SensitivePath("/database.sqlite3","db_backup", "critical",
        "SQLite database file exposed",
        ["SQLite format 3"], [], 16),

    # ── Debug / access logs ──────────────────────────────────────────────
    SensitivePath("/debug.log",       "debug_log", "medium",
        "Debug log file exposed",
        ["ERROR", "Exception", "Traceback", "Warning", "DEBUG"],
        ["text/plain"], 20,
        "Disable debug logging or restrict access to log files."),
    SensitivePath("/error.log",       "debug_log", "medium",
        "Error log file exposed",
        ["ERROR", "exception", "PHP Warning", "PHP Fatal"], [], 20),
    SensitivePath("/access.log",      "debug_log", "low",
        "Access log file exposed",
        ["GET /", "POST /", "200", "Mozilla"], [], 20),
    SensitivePath("/laravel.log",     "debug_log", "high",
        "Laravel application log exposed",
        ["local.ERROR", "local.INFO", "Illuminate\\", "Stack trace"], [], 20),
    SensitivePath("/storage/logs/laravel.log", "debug_log", "high",
        "Laravel log in storage directory exposed",
        ["local.ERROR", "Illuminate\\"], [], 20),

    # ── Version control ──────────────────────────────────────────────────
    SensitivePath("/.git/config",     "deploy_artifact", "high",
        "Git repository configuration exposed",
        ["[core]", "[remote", "repositoryformatversion", "[branch"],
        ["text/plain"], 10,
        "Block access to .git via web server configuration.",
        ["https://owasp.org/www-community/attacks/Path_Traversal"]),
    SensitivePath("/.git/HEAD",       "deploy_artifact", "medium",
        "Git HEAD reference exposed",
        ["ref:", "refs/heads/"], [], 5),
    SensitivePath("/.svn/entries",    "deploy_artifact", "medium",
        "Subversion metadata exposed",
        ["svn:"], [], 5),

    # ── Source maps ──────────────────────────────────────────────────────
    SensitivePath("/static/js/main.js.map", "source_map", "medium",
        "JavaScript source map exposed",
        ["version", "sources", "mappings"],
        ["application/json", "application/javascript"], 20,
        "Disable source map generation in production builds."),
    SensitivePath("/js/app.js.map",         "source_map", "medium",
        "JavaScript source map exposed",
        ["version", "sources", "mappings"], [], 20),
    SensitivePath("/bundle.js.map",         "source_map", "medium",
        "JavaScript source map exposed",
        ["version", "sources"], [], 20),

    # ── Archive / backup files ───────────────────────────────────────────
    SensitivePath("/backup.zip",      "archive", "high",
        "Site backup archive exposed",
        ["PK\x03\x04"], ["application/zip", "application/octet"], 4,
        "Remove backup archives from the web root."),
    SensitivePath("/backup.tar.gz",   "archive", "high",
        "Compressed backup archive exposed",
        ["\x1f\x8b"], ["application/gzip", "application/octet"], 2),
    SensitivePath("/www.zip",         "archive", "high",
        "Web root backup exposed",
        ["PK\x03\x04"], [], 4),
    SensitivePath("/site.zip",        "archive", "high",
        "Site archive exposed",
        ["PK\x03\x04"], [], 4),

    # ── Deployment artifacts ─────────────────────────────────────────────
    SensitivePath("/Dockerfile",           "deploy_artifact", "medium",
        "Dockerfile exposed",
        ["FROM ", "RUN ", "ENV ", "COPY ", "EXPOSE "], [], 10,
        "Block access to Dockerfile via web server rules."),
    SensitivePath("/docker-compose.yml",   "deploy_artifact", "medium",
        "Docker Compose file exposed",
        ["version:", "services:", "image:", "volumes:"], [], 10),
    SensitivePath("/docker-compose.yaml",  "deploy_artifact", "medium",
        "Docker Compose file exposed",
        ["version:", "services:", "image:"], [], 10),
    SensitivePath("/phpinfo.php",          "deploy_artifact", "medium",
        "PHP info page exposed",
        ["PHP Version", "phpinfo()", "PHP_OS", "DOCUMENT_ROOT"], [], 50,
        "Remove phpinfo.php from production servers.",
        ["https://owasp.org/www-community/attacks/Fingerprinting"]),
    SensitivePath("/server-status",        "deploy_artifact", "low",
        "Apache server-status page exposed",
        ["Apache Server Status", "Server Version", "Current Time"], [], 20,
        "Restrict access to /server-status to localhost."),
    SensitivePath("/server-info",          "deploy_artifact", "low",
        "Apache server-info page exposed",
        ["Apache Server Information", "Module Name"], [], 20),
]

_CATEGORY_FRAMEWORKS: Dict[str, List[str]] = {
    "env_config":      ["PCI_DSS", "ISO27001", "SOC2"],
    "db_backup":       ["PCI_DSS", "ISO27001"],
    "debug_log":       ["ISO27001", "GDPR"],
    "source_map":      ["ISO27001"],
    "archive":         ["PCI_DSS", "ISO27001"],
    "deploy_artifact": ["ISO27001"],
}


# ---------------------------------------------------------------------------
# HTTP fetcher
# ---------------------------------------------------------------------------

def _fetch(host: str, port: int, path: str, use_tls: bool) -> Tuple[int, str, bytes]:
    """GET a path; return (status, content_type, body_prefix). (0,"",b"") on error."""
    try:
        ctx = ssl.create_default_context() if use_tls else None
        if ctx:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        conn_cls = http.client.HTTPSConnection if use_tls else http.client.HTTPConnection
        conn = conn_cls(host, port, timeout=CONNECT_TIMEOUT)
        conn.connect()
        conn.sock.settimeout(READ_TIMEOUT)
        conn.request("GET", path, headers={
            "Host": host,
            "User-Agent": "Mozilla/5.0 (NorthHarv/security-scanner)",
            "Accept": "*/*",
            "Connection": "close",
        })
        resp = conn.getresponse()
        status = resp.status
        ct = resp.getheader("Content-Type", "")
        body = resp.read(MAX_RESPONSE_BYTES)
        conn.close()
        return status, ct, body
    except Exception:
        return 0, "", b""


def _confirms(body: bytes, sp: SensitivePath) -> bool:
    if len(body) < sp.min_body_bytes:
        return False
    if not sp.body_signatures:
        return True
    text = body.decode("utf-8", errors="replace")
    return any(sig in text or sig.encode() in body for sig in sp.body_signatures)


def _confidence(sp: SensitivePath, body: bytes) -> float:
    base = {"critical": 0.80, "high": 0.70, "medium": 0.60, "low": 0.50}.get(sp.severity, 0.55)
    text = body.decode("utf-8", errors="replace")
    hits = sum(1 for s in sp.body_signatures if s in text or s.encode() in body)
    if hits >= 2:
        base = min(0.98, base + 0.15)
    elif hits == 1:
        base = min(0.95, base + 0.08)
    return round(max(0.10, min(1.0, base)), 3)


def _safe_snippet(body: bytes) -> str:
    """Short excerpt with credential lines redacted."""
    lines = body.decode("utf-8", errors="replace").splitlines()[:30]
    safe = []
    for line in lines:
        if re.search(r"(?i)(password|secret|key|token|auth|credential)\s*[=:]\s*\S", line):
            lhs = re.split(r"[=:]", line, maxsplit=1)[0]
            safe.append(f"{lhs.strip()}=[REDACTED]")
        else:
            safe.append(line)
    return "\n".join(safe[:20])


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

@register_engine
class SensitiveFileEngine(DetectionEngine):
    """Probes HTTP/HTTPS services for exposed sensitive files."""

    name        = "sensitive_file_engine"
    version     = _VERSION
    description = ("Probes HTTP/HTTPS services for exposed environment configs, "
                   "database backups, source maps, deployment artifacts, and debug logs.")
    timeout_seconds = 90.0

    def validate_input(self, target: Any) -> bool:
        if not isinstance(target, dict):
            return False
        ip = target.get("ip", "")
        port = target.get("port", 0)
        if not ip or not port:
            return False
        http_status = target.get("http_status", 0)
        service = target.get("service_name", "") or ""
        return http_status != 0 or "http" in service.lower()

    def analyze(self, target: Dict[str, Any]) -> List[UnifiedFinding]:
        ip      = target["ip"]
        port    = target["port"]
        service = target.get("service_name", "") or ""
        use_tls = port in {443, 8443, 4443, 9443} or "https" in service.lower()
        base_url = f"{'https' if use_tls else 'http'}://{ip}:{port}"
        ts = _utcnow()

        findings: List[UnifiedFinding] = []
        seen: set = set()

        for sp in _PATHS:
            status, ct, body = _fetch(ip, port, sp.path, use_tls)
            if status not in (200, 206):
                continue
            if not _confirms(body, sp):
                continue

            body_hash = hashlib.sha256(body[:4096]).hexdigest()[:16]
            fp = f"{ip}:{port}{sp.path}:{body_hash}"
            if fp in seen:
                continue
            seen.add(fp)

            conf = _confidence(sp, body)
            text = body.decode("utf-8", errors="replace")
            matched = [s for s in sp.body_signatures if s in text or s.encode() in body][:5]

            findings.append(UnifiedFinding(
                finding_id=str(uuid.uuid4()),
                target=f"{ip}:{port}",
                asset_type="service",
                finding_type="sensitive_file",
                title=sp.description,
                description=(
                    f"{sp.path} returned HTTP {status}. "
                    f"Content confirmed as {sp.category.replace('_', ' ')}."
                ),
                severity=sp.severity,
                confidence=conf,
                verification_status="verified" if conf >= 0.80 else "probable",
                source_resource=f"{base_url}{sp.path}",
                evidence={
                    "path":        sp.path,
                    "http_status": status,
                    "content_type": ct,
                    "body_bytes":  len(body),
                    "body_hash":   body_hash,
                    "snippet":     _safe_snippet(body),
                    "matched_signatures": matched,
                    "category":    sp.category,
                },
                detection_engine=self.name,
                engine_version=self.version,
                first_observed=ts,
                last_observed=ts,
                finding_status="new",
                remediation=sp.remediation,
                references=list(sp.references),
                compliance_frameworks=_CATEGORY_FRAMEWORKS.get(sp.category, ["ISO27001"]),
                rule_id=f"SF_{sp.category.upper()}",
            ))

        return findings


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
