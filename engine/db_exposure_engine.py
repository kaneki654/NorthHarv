"""
engine/db_exposure_engine.py

Database Exposure Detection Engine for NorthHarv.

Identifies publicly accessible database interfaces and exposure indicators
for: Elasticsearch, OpenSearch, MongoDB, Redis, Memcached, CouchDB,
InfluxDB, Cassandra, Kibana, Grafana, Prometheus, and database admin panels
(phpMyAdmin, Adminer, Mongo Express, Redis Commander).

Detection is non-destructive:
  - Only reads publicly accessible API responses and banners.
  - Does not perform authentication.
  - Does not modify data.
  - Does not extract bulk records.
  - Reads at most 8 KB from any single response.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import re
import socket
import ssl
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from engine.base_engine import DetectionEngine, UnifiedFinding, register_engine

_VERSION           = "1.0.0"
MAX_RESPONSE_BYTES = 8 * 1024
CONNECT_TIMEOUT    = 4.0
READ_TIMEOUT       = 6.0

# ---------------------------------------------------------------------------
# Service definitions
# ---------------------------------------------------------------------------

@dataclass
class DbService:
    name:        str
    ports:       List[int]
    finding_type: str
    severity:    str
    description: str
    remediation: str
    references:  List[str] = field(default_factory=list)
    frameworks:  List[str] = field(default_factory=list)


_DB_SERVICES: List[DbService] = [
    DbService("Elasticsearch", [9200, 9300],
        "database_exposure", "critical",
        "Elasticsearch node publicly accessible without authentication",
        "Enable Elasticsearch security (xpack.security.enabled: true) and restrict port 9200/9300 to authorized networks.",
        ["https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html"],
        ["PCI_DSS", "ISO27001", "GDPR"]),
    DbService("OpenSearch",    [9200, 9300],
        "database_exposure", "critical",
        "OpenSearch node publicly accessible without authentication",
        "Enable OpenSearch security plugin and restrict port 9200/9300.",
        [], ["PCI_DSS", "ISO27001"]),
    DbService("Kibana",        [5601],
        "database_exposure", "high",
        "Kibana dashboard publicly accessible",
        "Enable Kibana authentication and restrict access to authorized networks.",
        [], ["PCI_DSS", "ISO27001"]),
    DbService("Redis",         [6379],
        "database_exposure", "critical",
        "Redis server publicly accessible without authentication",
        "Set a Redis password (requirepass), bind to 127.0.0.1, and use firewall rules.",
        ["https://redis.io/docs/manual/security/"],
        ["PCI_DSS", "ISO27001"]),
    DbService("Memcached",     [11211],
        "database_exposure", "critical",
        "Memcached server publicly accessible",
        "Bind Memcached to 127.0.0.1 and block port 11211 at the firewall.",
        [], ["PCI_DSS", "ISO27001"]),
    DbService("MongoDB",       [27017, 27018, 27019],
        "database_exposure", "critical",
        "MongoDB instance publicly accessible",
        "Enable MongoDB authentication, bind to 127.0.0.1, and restrict access.",
        ["https://www.mongodb.com/docs/manual/security/"],
        ["PCI_DSS", "ISO27001", "GDPR"]),
    DbService("CouchDB",       [5984],
        "database_exposure", "high",
        "CouchDB instance publicly accessible",
        "Enable CouchDB authentication and restrict access.",
        [], ["ISO27001"]),
    DbService("InfluxDB",      [8086],
        "database_exposure", "high",
        "InfluxDB instance publicly accessible",
        "Enable InfluxDB authentication and restrict access.",
        [], ["ISO27001"]),
    DbService("Cassandra",     [9042, 9160],
        "database_exposure", "critical",
        "Apache Cassandra node publicly accessible",
        "Enable Cassandra authentication and restrict access.",
        [], ["PCI_DSS", "ISO27001"]),
    DbService("ZooKeeper",     [2181],
        "database_exposure", "high",
        "Apache ZooKeeper instance publicly accessible",
        "Restrict ZooKeeper access to cluster members only.",
        [], ["ISO27001"]),
    DbService("Prometheus",    [9090],
        "database_exposure", "medium",
        "Prometheus metrics endpoint publicly accessible",
        "Add authentication/proxy in front of Prometheus or bind to localhost.",
        [], ["ISO27001"]),
    DbService("Grafana",       [3000],
        "database_exposure", "medium",
        "Grafana dashboard accessible (default credentials may be active)",
        "Change Grafana default credentials and restrict access.",
        [], ["ISO27001"]),
]

# Admin panel paths to probe on HTTP services: (path, title_signature, panel_name, severity)
_ADMIN_PATHS: List[Tuple[str, str, str, str]] = [
    ("/phpmyadmin/",     "phpMyAdmin",          "phpMyAdmin",      "high"),
    ("/phpmyadmin",      "phpMyAdmin",          "phpMyAdmin",      "high"),
    ("/pma/",            "phpMyAdmin",          "phpMyAdmin",      "high"),
    ("/adminer.php",     "Adminer",             "Adminer",         "high"),
    ("/adminer/",        "Adminer",             "Adminer",         "high"),
    ("/_utils/",         "CouchDB",             "Fauxton (CouchDB)", "high"),
    ("/mongo-express/",  "Mongo Express",       "Mongo Express",   "critical"),
    ("/rediscommander/", "Redis Commander",     "Redis Commander", "critical"),
    ("/redisinsight/",   "RedisInsight",        "RedisInsight",    "medium"),
    ("/kibana/",         "Kibana",              "Kibana",          "high"),
    ("/app/kibana",      "Kibana",              "Kibana",          "high"),
    ("/elastic/",        "Elasticsearch",       "Elasticsearch",   "critical"),
]

# ---------------------------------------------------------------------------
# TCP helpers
# ---------------------------------------------------------------------------

def _tcp_banner(ip: str, port: int) -> bytes:
    try:
        s = socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT)
        s.settimeout(READ_TIMEOUT)
        try:
            banner = s.recv(1024)
        except Exception:
            banner = b""
        finally:
            s.close()
        return banner
    except Exception:
        return b""


def _send_recv(ip: str, port: int, payload: bytes) -> bytes:
    try:
        s = socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT)
        s.settimeout(READ_TIMEOUT)
        s.sendall(payload)
        try:
            resp = s.recv(4096)
        except Exception:
            resp = b""
        finally:
            s.close()
        return resp
    except Exception:
        return b""


# ---------------------------------------------------------------------------
# HTTP fetcher
# ---------------------------------------------------------------------------

def _http_get(ip: str, port: int, path: str, use_tls: bool = False) -> Tuple[int, str, bytes]:
    try:
        ctx = ssl.create_default_context() if use_tls else None
        if ctx:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        conn_cls = http.client.HTTPSConnection if use_tls else http.client.HTTPConnection
        conn = conn_cls(ip, port, timeout=CONNECT_TIMEOUT)
        conn.connect()
        conn.sock.settimeout(READ_TIMEOUT)
        conn.request("GET", path, headers={
            "Host": ip,
            "User-Agent": "Mozilla/5.0 (NorthHarv/security-scanner)",
            "Accept": "application/json, text/html, */*",
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


# ---------------------------------------------------------------------------
# Service-specific probes
# ---------------------------------------------------------------------------

def _probe_elasticsearch(ip: str, port: int) -> Optional[Dict[str, Any]]:
    status, _, body = _http_get(ip, port, "/")
    if status != 200:
        return None
    if b"cluster_name" not in body and b"tagline" not in body:
        return None
    try:
        data = json.loads(body)
        if "cluster_name" in data or "tagline" in data:
            return {
                "cluster_name": data.get("cluster_name", ""),
                "version":      data.get("version", {}).get("number", ""),
                "tagline":      data.get("tagline", ""),
                "name":         data.get("name", ""),
            }
    except Exception:
        pass
    return None


def _probe_redis(ip: str, port: int) -> Optional[Dict[str, Any]]:
    resp = _send_recv(ip, port, b"PING\r\n")
    if b"+PONG" not in resp:
        return None
    info_resp = _send_recv(ip, port, b"INFO server\r\n")
    version = ""
    m = re.search(rb"redis_version:([^\r\n]+)", info_resp)
    if m:
        version = m.group(1).decode("utf-8", errors="replace").strip()
    return {"redis_version": version, "ping_response": "+PONG"}


def _probe_memcached(ip: str, port: int) -> Optional[Dict[str, Any]]:
    resp = _send_recv(ip, port, b"stats\r\n")
    if b"STAT " not in resp:
        return None
    version = ""
    m = re.search(rb"STAT version ([^\r\n]+)", resp)
    if m:
        version = m.group(1).decode("utf-8", errors="replace").strip()
    return {"version": version}


def _probe_mongodb(ip: str, port: int) -> Optional[Dict[str, Any]]:
    # Minimal OP_MSG isMaster
    msg = bytes([
        0x41,0x00,0x00,0x00, 0x01,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0xdd,0x07,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,
        0x2d,0x00,0x00,0x00,
        0x10,0x69,0x73,0x4d,0x61,0x73,0x74,0x65,0x72,0x00,
        0x01,0x00,0x00,0x00,
        0x02,0x24,0x64,0x62,0x00,0x06,0x00,0x00,0x00,
        0x61,0x64,0x6d,0x69,0x6e,0x00, 0x00,
    ])
    resp = _send_recv(ip, port, msg)
    if len(resp) > 16 and b"ismaster" in resp.lower():
        return {"responded": True, "length": len(resp)}
    banner = _tcp_banner(ip, port)
    if b"MongoDB" in banner or b"mongod" in banner.lower():
        return {"banner": banner[:200].decode("utf-8", errors="replace")}
    return None


def _probe_couchdb(ip: str, port: int) -> Optional[Dict[str, Any]]:
    status, _, body = _http_get(ip, port, "/")
    if status == 200 and b"CouchDB" in body:
        try:
            data = json.loads(body)
            return {"version": data.get("version", ""), "couchdb": data.get("couchdb", "")}
        except Exception:
            return {"raw": body[:200].decode("utf-8", errors="replace")}
    return None


def _probe_influxdb(ip: str, port: int) -> Optional[Dict[str, Any]]:
    status, _, _ = _http_get(ip, port, "/ping")
    if status in (200, 204):
        return {"ping_status": status}
    return None


# ---------------------------------------------------------------------------
# Admin panel probe
# ---------------------------------------------------------------------------

def _probe_admin_panels(ip: str, port: int, service: str) -> List[Dict[str, Any]]:
    use_tls = port in {443, 8443} or "https" in service.lower()
    hits = []
    for path, title_sig, panel_name, severity in _ADMIN_PATHS:
        status, _, body = _http_get(ip, port, path, use_tls)
        if status not in (200, 401, 403):
            continue
        text = body.decode("utf-8", errors="replace")
        if title_sig.lower() not in text.lower():
            continue
        hits.append({
            "path":        path,
            "panel":       panel_name,
            "severity":    severity,
            "http_status": status,
            "body_hash":   hashlib.sha256(body[:2048]).hexdigest()[:16],
            "snippet":     text[:300],
        })
    return hits


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

@register_engine
class DatabaseExposureEngine(DetectionEngine):
    """
    Identifies publicly accessible database instances and admin panels.
    Non-destructive: read-only probes, no authentication, no data extraction.
    """

    name        = "db_exposure_engine"
    version     = _VERSION
    description = ("Identifies publicly accessible database instances (Elasticsearch, "
                   "Redis, MongoDB, Memcached, CouchDB, InfluxDB) and database admin "
                   "panels (phpMyAdmin, Adminer, Mongo Express, Redis Commander).")
    timeout_seconds = 60.0

    def validate_input(self, target: Any) -> bool:
        return isinstance(target, dict) and bool(target.get("ip")) and bool(target.get("port"))

    def analyze(self, target: Dict[str, Any]) -> List[UnifiedFinding]:
        ip      = target["ip"]
        port    = int(target["port"])
        service = target.get("service_name", "") or ""
        ts      = _utcnow()
        findings: List[UnifiedFinding] = []

        # --- Raw DB protocol probes ---
        for db in _DB_SERVICES:
            if port not in db.ports:
                continue

            info: Optional[Dict[str, Any]] = None
            if db.name in ("Elasticsearch", "OpenSearch"):
                info = _probe_elasticsearch(ip, port)
            elif db.name == "Redis":
                info = _probe_redis(ip, port)
            elif db.name == "Memcached":
                info = _probe_memcached(ip, port)
            elif db.name == "MongoDB":
                info = _probe_mongodb(ip, port)
            elif db.name == "CouchDB":
                info = _probe_couchdb(ip, port)
            elif db.name == "InfluxDB":
                info = _probe_influxdb(ip, port)
            elif db.name in ("Kibana", "Grafana", "Prometheus", "Cassandra", "ZooKeeper"):
                # Kibana/Grafana/Prometheus handled via admin-panel probe; Cassandra/ZK by banner
                banner = _tcp_banner(ip, port)
                if banner:
                    info = {"banner": banner[:200].decode("utf-8", errors="replace")}

            if info is None:
                continue

            version_str = str(
                info.get("version") or info.get("redis_version") or
                info.get("couchdb") or ""
            )
            conf = 0.95 if info.get("responded") or info.get("ping_response") else 0.75

            findings.append(UnifiedFinding(
                finding_id=str(uuid.uuid4()),
                target=f"{ip}:{port}",
                asset_type="service",
                finding_type=db.finding_type,
                title=db.description,
                description=(
                    f"{db.name} on {ip}:{port} responded to an unauthenticated probe. "
                    + (f"Version: {version_str}. " if version_str else "")
                    + "Database contents may be directly accessible."
                ),
                severity=db.severity,
                confidence=conf,
                verification_status="verified" if conf >= 0.90 else "probable",
                source_resource=f"{ip}:{port}",
                evidence={
                    "service":        db.name,
                    "port":           port,
                    "probe_response": info,
                    "version":        version_str,
                },
                detection_engine=self.name,
                engine_version=self.version,
                first_observed=ts,
                last_observed=ts,
                finding_status="new",
                remediation=db.remediation,
                references=list(db.references),
                compliance_frameworks=list(db.frameworks),
                rule_id=f"DBE_{db.name.upper().replace(' ', '_')}",
            ))

        # --- Admin panel probes on HTTP ports ---
        http_ports = {80, 443, 8080, 8443, 3000, 5601, 5984, 8086, 9090, 9200}
        is_http = "http" in service.lower() or port in http_ports
        if is_http:
            for panel in _probe_admin_panels(ip, port, service):
                conf = 0.90 if panel["http_status"] == 200 else 0.70
                findings.append(UnifiedFinding(
                    finding_id=str(uuid.uuid4()),
                    target=f"{ip}:{port}",
                    asset_type="service",
                    finding_type="admin_panel_exposed",
                    title=f"{panel['panel']} admin panel publicly accessible",
                    description=(
                        f"{panel['panel']} was found at {panel['path']} on {ip}:{port} "
                        f"(HTTP {panel['http_status']}). Database administration interfaces "
                        "should not be publicly accessible."
                    ),
                    severity=panel["severity"],
                    confidence=conf,
                    verification_status="verified" if conf >= 0.85 else "probable",
                    source_resource=f"http://{ip}:{port}{panel['path']}",
                    evidence={
                        "path":        panel["path"],
                        "panel":       panel["panel"],
                        "http_status": panel["http_status"],
                        "body_hash":   panel["body_hash"],
                        "snippet":     panel["snippet"],
                    },
                    detection_engine=self.name,
                    engine_version=self.version,
                    first_observed=ts,
                    last_observed=ts,
                    finding_status="new",
                    remediation=(
                        f"Restrict access to {panel['panel']} behind a VPN or IP allowlist. "
                        "Change default credentials if any are active."
                    ),
                    references=["https://owasp.org/www-project-top-ten/"],
                    compliance_frameworks=["PCI_DSS", "ISO27001"],
                    rule_id=f"DBE_ADMIN_{panel['panel'].upper().replace(' ', '_')[:30]}",
                ))

        return findings


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
