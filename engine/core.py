#!/usr/bin/env python3
"""
CyberScan v3 — single-file cyberspace search engine.
Stdlib only. Optional accelerators (masscan, nmap, cryptography, geoip2) auto-detected.

COMMANDS
    init                              create DB + allowlist template
    sync-feeds [--years ...]          sync NVD + CISA KEV + EPSS online
    scan --cidr X [--ports ...]       one-shot scan of authorized range
    daemon --interval H [--once]      continuous re-scanning, H hours apart
    query "expr" [--facets ...]       search
    diff --round-a N --round-b M      compare two scan rounds
    history --ip X --port N           per-host observation history
    serve --port 8080                 HTTP API
    shard --cidr X --workers N        emit sub-CIDRs for parallel workers
    import-csv path                   import IPtoASN CSV
    stats                             summary counts
"""
import argparse, asyncio, bisect, csv, gzip, hashlib, ipaddress, itertools
import json, logging, lzma, math, os, re, shlex, signal, socket, sqlite3
import ssl, struct, subprocess, sys, threading, time, urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from engine.card_detector import scan_banner as _cd_scan_banner, CardFinding as _CardFinding
except ImportError:
    try:
        from card_detector import scan_banner as _cd_scan_banner, CardFinding as _CardFinding
    except ImportError:
        _cd_scan_banner = None  # type: ignore
        _CardFinding = None     # type: ignore

# ============================================================================
# CONFIG
# ============================================================================
DB_PATH        = os.getenv("CYBERSCAN_DB", "cyberscan.db")
ALLOWLIST_FILE = os.getenv("CYBERSCAN_ALLOWLIST", "allowlist.txt")
MASSCAN        = os.getenv("MASSCAN_BIN", "masscan")
NMAP           = os.getenv("NMAP_BIN", "nmap")
GEOIP_DB       = os.getenv("GEOIP_DB", "")
ASN_CSV        = os.getenv("ASN_CSV", "")
CONCURRENCY    = int(os.getenv("CONCURRENCY", "512"))
TIMEOUT        = float(os.getenv("TIMEOUT", "1.0"))
RATE_PPS       = int(os.getenv("RATE_PPS", "10000"))
NVD_CACHE_DIR  = os.getenv("NVD_CACHE", "nvd_cache")
NVD_FEED_BASE  = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download"
KEV_URL        = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL       = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 631, 993, 995, 1080, 1433, 1521, 1723, 2049, 2082, 2083,
    2375, 2376, 3000, 3306, 3389, 4443, 5000, 5432, 5555, 5601, 5900,
    6379, 7001, 7002, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000,
    9090, 9200, 9300, 10000, 11211, 27017,
]
HOT_PORTS     = {22, 80, 443, 3389, 8080, 8443}
TLS_PORTS     = {443, 8443, 465, 993, 995, 990, 4443, 9443, 2376}
PASSIVE_PORTS = {21, 22, 23, 25, 110, 143, 587, 3306, 6379, 11211, 27017,
                 1883, 5060, 5900, 9200}

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)-7s %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger("cyberscan")

# ============================================================================
# MODELS
# ============================================================================
@dataclass
class Geo:
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[int] = None
    org: Optional[str] = None

@dataclass
class TLSInfo:
    subject_cn: Optional[str] = None
    issuer_cn: Optional[str] = None
    san: List[str] = field(default_factory=list)
    sha256: Optional[str] = None
    serial: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    days_to_expiry: Optional[int] = None
    self_signed: bool = False
    key_type: Optional[str] = None
    key_bits: Optional[int] = None
    sig_alg: Optional[str] = None
    ocsp_url: Optional[str] = None
    crl_url: Optional[str] = None
    chain: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class Service:
    ip: str
    port: int
    protocol: str = "tcp"
    banner: str = ""
    service_name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: List[str] = field(default_factory=list)
    os: str = ""
    http_title: str = ""
    http_server: str = ""
    tls: Optional[TLSInfo] = None
    geo: Optional[Geo] = None
    cves: List[str] = field(default_factory=list)
    kev: List[str] = field(default_factory=list)
    cvss_max: float = 0.0
    epss_max: float = 0.0
    scan_round: int = 0
    first_seen: str = ""
    last_seen: str = ""
    # intelligence layer
    risk_score: int = 0
    techs: List[str] = field(default_factory=list)
    hostname: str = ""
    domain: str = ""
    tags: str = ""
    icon_hash: int = 0
    jarm: str = ""
    hassh: str = ""
    ja3s: str = ""
    http_status: int = 0
    http_headers: str = ""
    waf: str = ""
    cloud_provider: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)

# ============================================================================
# DER FALLBACK PARSER
# ============================================================================
def _der_read(d, i):
    tag = d[i]; i += 1
    ln = d[i]; i += 1
    if ln & 0x80:
        n = ln & 0x7F; ln = int.from_bytes(d[i:i+n], "big"); i += n
    return tag, d[i:i+ln], i + ln

def _oid_str(b):
    if not b: return ""
    p = [b[0] // 40, b[0] % 40]; v = 0
    for c in b[1:]:
        v = (v << 7) | (c & 0x7F)
        if not (c & 0x80):
            p.append(v); v = 0
    return ".".join(map(str, p))

def _parse_name(raw):
    out = {}
    _, body, _ = _der_read(raw, 0); i = 0
    while i < len(body):
        _, rdn, i = _der_read(body, i); j = 0
        while j < len(rdn):
            _, av, j = _der_read(rdn, j)
            _, oid, k = _der_read(av, 0)
            _, val, _ = _der_read(av, k)
            try: sval = val.decode("utf-8", "replace")
            except Exception: sval = ""
            out[_oid_str(oid)] = sval
    return out

def _parse_time(raw):
    tag, val, _ = _der_read(raw, 0)
    s = val.decode("ascii", "ignore")
    if tag == 0x17 and len(s) >= 12:
        yy = int(s[:2]); y = 2000+yy if yy < 50 else 1900+yy
        return f"{y}{s[2:]}"
    return s

def parse_tls_der(der: bytes) -> TLSInfo:
    info = TLSInfo(sha256=hashlib.sha256(der).hexdigest(),
                   self_signed=False)
    try:
        _, cb, _ = _der_read(der, 0)
        _, tbs, _ = _der_read(cb, 0)
        i = 0
        if tbs[i] == 0xA0: _, _, i = _der_read(tbs, i)
        _, _, i = _der_read(tbs, i)       # serial
        _, _, i = _der_read(tbs, i)       # sig alg
        _, issuer_raw, i = _der_read(tbs, i)
        _, validity_raw, i = _der_read(tbs, i)
        _, subject_raw, i = _der_read(tbs, i)
        issuer  = _parse_name(issuer_raw)
        subject = _parse_name(subject_raw)
        info.subject_cn = subject.get("2.5.4.3")
        info.issuer_cn  = issuer.get("2.5.4.3")
        info.self_signed = (info.subject_cn is not None and
                            info.subject_cn == info.issuer_cn)
        _, vb, j = _der_read(validity_raw, 0)
        _, _, j = _der_read(validity_raw, j)
        info.not_before = _parse_time(vb)
        info.not_after  = _parse_time(validity_raw[j:])
        try:
            na = datetime.strptime(info.not_after[:12], "%Y%m%d%H%M%S").replace(
                tzinfo=timezone.utc)
            info.days_to_expiry = (na - datetime.now(timezone.utc)).days
        except Exception:
            pass
    except Exception:
        pass
    return info

# ============================================================================
# FINGERPRINTING — ~40 rules + CPE map
# ============================================================================
CPE_MAP = {
    "openssh":      ("openbsd", "openssh"),
    "dropbear":     ("matt_johnston", "dropbear_ssh"),
    "nginx":        ("nginx", "nginx"),
    "apache":       ("apache", "http_server"),
    "httpd":        ("apache", "http_server"),
    "iis":          ("microsoft", "internet_information_services"),
    "microsoft-iis":("microsoft", "internet_information_services"),
    "lighttpd":     ("lighttpd", "lighttpd"),
    "caddy":        ("caddyserver", "caddy"),
    "litespeed":    ("litespeedtech", "litespeed_web_server"),
    "vsftpd":       ("beasts", "vsftpd"),
    "proftpd":      ("proftpd", "proftpd"),
    "pure-ftpd":    ("pure-ftpd", "pure-ftpd"),
    "filezilla":    ("filezilla-project", "filezilla_server"),
    "postfix":      ("postfix", "postfix"),
    "exim":         ("exim", "exim"),
    "sendmail":     ("sendmail", "sendmail"),
    "exchange":     ("microsoft", "exchange_server"),
    "dovecot":      ("dovecot", "dovecot"),
    "courier":      ("courier-mta", "courier"),
    "mysql":        ("oracle", "mysql"),
    "mariadb":      ("mariadb", "mariadb"),
    "postgresql":   ("postgresql", "postgresql"),
    "mssql":        ("microsoft", "sql_server"),
    "oracle db":    ("oracle", "database_server"),
    "mongodb":      ("mongodb", "mongodb"),
    "redis":        ("redis", "redis"),
    "memcached":    ("memcached", "memcached"),
    "elasticsearch":("elastic", "elasticsearch"),
    "kibana":       ("elastic", "kibana"),
    "grafana":      ("grafana", "grafana"),
    "jenkins":      ("jenkins", "jenkins"),
    "tomcat":       ("apache", "tomcat"),
    "jetty":        ("eclipse", "jetty"),
    "docker":       ("docker", "docker"),
    "kubernetes":   ("kubernetes", "kubernetes"),
    "samba":        ("samba", "samba"),
    "smbd":         ("samba", "samba"),
    "vnc":          ("realvnc", "vnc"),
    "rabbitmq":     ("vmware", "rabbitmq"),
    "couchdb":      ("apache", "couchdb"),
    "mosquitto":    ("eclipse", "mosquitto"),
    "cisco":        ("cisco", "ios"),
    "mikrotik":     ("mikrotik", "routeros"),
    "ubiquiti":     ("ui", "unifi"),
    "openssl":      ("openssl", "openssl"),
    "openssl-lib":  ("openssl", "openssl"),
}

def _cpe_for(product: str, version: str) -> Optional[str]:
    if not product: return None
    p = product.lower().strip().split()[0]
    vendor, prod = CPE_MAP.get(p, (None, None))
    if not vendor: return None
    v = version if version else "*"
    return f"cpe:2.3:a:{vendor}:{prod}:{v}:*:*:*:*:*:*:*"

def _http_fields(b: str) -> Tuple[str, str]:
    title, server = "", ""
    m = re.search(r"^Server:\s*(\S[^\r\n]*)", b, re.I | re.M)
    if m: server = m.group(1).strip()
    m = re.search(r"<title[^>]*>([^<]{1,300})</title>", b, re.I | re.S)
    if m: title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title, server

def _http_meta(b: str) -> Tuple[str, int]:
    """Status code and raw header block of an HTTP response banner.

    Technology, WAF and cloud detection all match against response headers,
    and the http.status: operator reads the code. Both were left empty for
    every scanned host because nothing ever extracted them from the banner,
    which silently disabled every header-based signature.
    """
    if not b or not b.lstrip()[:5].upper().startswith("HTTP/"):
        return "", 0
    status = 0
    m = re.match(r"\s*HTTP/\d(?:\.\d)?\s+(\d{3})", b)
    if m:
        status = int(m.group(1))
    head = re.split(r"\r?\n\r?\n", b, maxsplit=1)[0]
    lines = [l.strip() for l in head.splitlines()[1:] if l.strip()]
    return "\n".join(lines)[:4000], status

def fingerprint(banner: str, port: int) -> Dict[str, Any]:
    out = {"service_name": "", "product": "", "version": "",
           "extrainfo": "", "http_title": "", "http_server": "",
           "http_headers": "", "http_status": 0, "cpe": []}
    b = banner or ""
    title, server = _http_fields(b)
    out["http_title"], out["http_server"] = title, server
    out["http_headers"], out["http_status"] = _http_meta(b)

    # SSH
    m = re.search(r"SSH-([\d.]+)-(\S+)", b)
    if m:
        out["service_name"] = "ssh"; out["version"] = m.group(1)
        vm = re.match(r"([A-Za-z_]+)[_ ]([0-9][^\s]*)", m.group(2))
        if vm: out["product"] = vm.group(1); out["version"] = vm.group(2)
        else:  out["product"] = m.group(2).split("_")[0]
        if re.search(r"dropbear", m.group(2), re.I): out["product"] = "Dropbear"
        elif re.search(r"openssh", m.group(2), re.I): out["product"] = "OpenSSH"
        cpe = _cpe_for(out["product"], out["version"])
        if cpe: out["cpe"] = [cpe]
        return out

    # HTTP/S
    if re.search(r"^HTTP/[\d.]+", b) or re.search(r"^Server:", b, re.I | re.M):
        out["service_name"] = "https" if port in TLS_PORTS else "http"
        srv = (server or "").lower()
        if "nginx" in srv:        out["product"], _ = "nginx",     None
        elif "apache" in srv:     out["product"] = "Apache"
        elif "microsoft-iis" in srv or "iis" in srv: out["product"] = "Microsoft-IIS"
        elif "lighttpd" in srv:   out["product"] = "lighttpd"
        elif "litespeed" in srv:  out["product"] = "LiteSpeed"
        elif "caddy" in srv:      out["product"] = "Caddy"
        elif "cloudflare" in srv: out["product"] = "Cloudflare"
        else:
            pm = re.match(r"([\w.\-]+)/([0-9][\w.]*)", server or "")
            if pm: out["product"], out["version"] = pm.group(1), pm.group(2)
        if not out["version"] and server:
            vm = re.search(r"/([0-9][\w.]*)", server)
            if vm: out["version"] = vm.group(1)
        xp = re.search(r"^X-Powered-By:\s*(\S+)", b, re.I | re.M)
        if xp: out["extrainfo"] = xp.group(1)
        cpe = _cpe_for(out["product"], out["version"])
        if cpe: out["cpe"] = [cpe]
        return out

    # FTP / SMTP
    if re.match(r"^220[\s\-]", b):
        if port == 21: out["service_name"] = "ftp"
        else:          out["service_name"] = "smtp"
        low = b.lower()
        for prod in ("vsftpd","proftpd","pure-ftpd","filezilla","postfix",
                     "exim","sendmail","exchange","microsoft esmtp"):
            if prod in low:
                out["product"] = prod.title() if prod != "vsftpd" else "vsftpd"
                m = re.search(r"([\d]+\.[\d.]+)", b)
                if m: out["version"] = m.group(1)
                break
        cpe = _cpe_for(out["product"], out["version"])
        if cpe: out["cpe"] = [cpe]
        return out

    # IMAP / POP3
    if re.match(r"^\* OK", b):
        out["service_name"] = "imap" if port == 143 else "pop3"
        low = b.lower()
        for prod in ("dovecot","courier","exchange"):
            if prod in low:
                out["product"] = prod.title()
                m = re.search(r"([\d]+\.[\d.]+)", b)
                if m: out["version"] = m.group(1)
                break
        return out
    if re.match(r"^\+OK", b):
        out["service_name"] = "pop3"
        low = b.lower()
        for prod in ("dovecot","courier","exchange"):
            if prod in low:
                out["product"] = prod.title(); break
        return out

    # MySQL
    if port == 3306 and len(b) >= 5:
        raw = b.encode("latin-1", "ignore")
        if len(raw) > 5 and raw[4] == 0x0A:
            try:
                end = raw.index(b"\x00", 5)
                out["service_name"] = "mysql"
                out["product"] = "MySQL"
                out["version"] = raw[5:end].decode("latin-1", "ignore").strip("-")
                if "mariadb" in out["version"].lower():
                    out["product"] = "MariaDB"
                cpe = _cpe_for(out["product"], out["version"])
                if cpe: out["cpe"] = [cpe]
            except ValueError: pass
        return out

    # PostgreSQL
    if port == 5432:
        out["service_name"] = "postgresql"
        out["product"] = "PostgreSQL"
        return out

    # Redis
    if b.startswith(("+PONG","-ERR","-NOAUTH","+OK","$")):
        out["service_name"] = "redis"; out["product"] = "Redis"
        m = re.search(r"redis_version:([\d.]+)", b)
        if m: out["version"] = m.group(1)
        cpe = _cpe_for("redis", out["version"])
        if cpe: out["cpe"] = [cpe]
        return out

    # Elasticsearch
    if '"cluster_name"' in b or '"tagline"' in b or '"version":{"number"' in b:
        out["service_name"] = "elasticsearch"; out["product"] = "Elasticsearch"
        m = re.search(r'"number"\s*:\s*"([\d.]+)"', b)
        if m: out["version"] = m.group(1)
        cpe = _cpe_for("elasticsearch", out["version"])
        if cpe: out["cpe"] = [cpe]
        return out

    # Kibana
    if '"version"' in b and '"buildNum"' in b:
        out["service_name"] = "kibana"; out["product"] = "Kibana"
        m = re.search(r'"version"\s*:\s*"([\d.]+)"', b)
        if m: out["version"] = m.group(1)
        return out

    # MongoDB / RDP / Memcached / Docker / K8s
    if port == 27017: out.update(service_name="mongodb", product="MongoDB"); return out
    if port == 3389:  out.update(service_name="ms-wbt-server", product="RDP"); return out
    if port == 11211: out.update(service_name="memcached", product="memcached"); return out
    if port == 2375 or port == 2376:
        out["service_name"] = "docker"
        out["product"] = "Docker"
        if b'"ApiVersion"' in b or b'/version' in b or "Docker" in b:
            m = re.search(r'"Version"\s*:\s*"([\d.]+)"', b)
            if m: out["version"] = m.group(1)
        return out
    if port == 6443 or "kubernetes" in b.lower():
        out["service_name"] = "kubernetes-api"; out["product"] = "Kubernetes"
        return out
    if port == 1883 or "mqtt" in b.lower():
        out["service_name"] = "mqtt"; out["product"] = "MQTT"
        return out
    if port == 5900:
        out["service_name"] = "vnc"; out["product"] = "VNC"; return out
    if port == 5060:
        out["service_name"] = "sip"; out["product"] = "SIP"; return out
    if port == 554:
        out["service_name"] = "rtsp"; out["product"] = "RTSP"; return out
    if port == 631:
        out["service_name"] = "ipp"; out["product"] = "CUPS/IPP"; return out
    if port == 445 or port == 139:
        out["service_name"] = "smb"; out["product"] = "Samba/SMB"; return out
    if port == 389 or port == 636:
        out["service_name"] = "ldap"; out["product"] = "LDAP"; return out

    # Router / appliance banners
    low = b.lower()
    if "cisco" in low:
        out["service_name"] = "ssh" if "ssh" in low else ""
        out["product"] = "Cisco IOS"
        m = re.search(r"version\s+([\d.]+)", b, re.I)
        if m: out["version"] = m.group(1)
        return out
    if "mikrotik" in low or "routeros" in low:
        out["service_name"] = "ssh"; out["product"] = "MikroTik RouterOS"
        m = re.search(r"([\d]+\.[\d.]+)", b)
        if m: out["version"] = m.group(1)
        return out
    if "ubiquiti" in low or "unifi" in low:
        out["product"] = "Ubiquiti UniFi"; return out

    # Generic "Xxx/1.2.3" fallback
    m = re.search(r"([A-Za-z][\w.\-]{2,})[\s/]([0-9]+\.[0-9][\w.]*)", b)
    if m: out["product"], out["version"] = m.group(1), m.group(2)
    cpe = _cpe_for(out["product"], out["version"])
    if cpe: out["cpe"] = [cpe]
    return out

# ============================================================================
# TLS GRAB (rich)
# ============================================================================
def _extract_cert_rich(der: bytes) -> Optional[TLSInfo]:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
        c = x509.load_der_x509_certificate(der)
        def cn(n):
            try: return n.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            except Exception: return None
        san = []
        ocsp = crl = None
        try:
            san = [str(v.value) for v in c.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value][:100]
        except Exception: pass
        try:
            aia = c.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
            for d in aia:
                if d.access_method == x509.AuthorityInformationAccessOID.OCSP:
                    ocsp = d.access_location.value
                elif d.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
                    crl = d.access_location.value
        except Exception: pass
        pub = c.public_key()
        key_type, key_bits = None, None
        if isinstance(pub, rsa.RSAPublicKey):
            key_type, key_bits = "RSA", pub.key_size
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            key_type, key_bits = "ECDSA", pub.curve.key_size
        elif isinstance(pub, dsa.DSAPublicKey):
            key_type, key_bits = "DSA", pub.key_size
        info = TLSInfo(
            subject_cn=cn(c.subject), issuer_cn=cn(c.issuer),
            san=san, sha256=c.fingerprint(hashes.SHA256()).hex(),
            serial=format(c.serial_number, "x"),
            not_before=c.not_valid_before_utc.isoformat(),
            not_after=c.not_valid_after_utc.isoformat(),
            self_signed=(cn(c.subject) == cn(c.issuer) and
                         c.subject == c.issuer),
            key_type=key_type, key_bits=key_bits,
            sig_alg=c.signature_algorithm_oid._name if hasattr(
                c.signature_algorithm_oid, "_name") else str(c.signature_algorithm_oid),
            ocsp_url=ocsp, crl_url=crl,
        )
        try:
            info.days_to_expiry = (
                c.not_valid_after_utc - datetime.now(timezone.utc)).days
        except Exception: pass
        return info
    except Exception:
        return None

def grab_tls(ip: str, port: int) -> Tuple[str, Optional[TLSInfo]]:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        raw = socket.create_connection((ip, port), timeout=TIMEOUT)
        ssock = ctx.wrap_socket(raw, server_hostname=ip)
        der = ssock.getpeercert(binary_form=True)
        chain_info: List[Dict[str, Any]] = []
        try:
            for c in ssock.get_verified_chain() if hasattr(ssock, "get_verified_chain") else []:
                chain_info.append({"subject": dict(x[0] for x in c.get("subject", [])),
                                   "issuer":  dict(x[0] for x in c.get("issuer", []))})
        except Exception:
            pass
        banner = ""
        try:
            ssock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            banner = ssock.recv(2048).decode("latin-1", "ignore")
        except Exception: pass
        ssock.close()
        tls = None
        if der:
            tls = _extract_cert_rich(der) or parse_tls_der(der)
            if tls:
                tls.chain = chain_info
        return banner.strip(), tls
    except Exception:
        return "", None

def grab_plain(ip: str, port: int) -> str:
    try:
        s = socket.create_connection((ip, port), timeout=TIMEOUT)
        s.settimeout(TIMEOUT)
        if port not in PASSIVE_PORTS:
            try: s.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            except Exception: pass
        buf = b""
        try:
            while len(buf) < 4096:
                c = s.recv(1024)
                if not c: break
                buf += c
                if len(buf) >= 1024: break
        except socket.timeout: pass
        s.close()
        return buf.decode("latin-1", "ignore").strip()
    except Exception:
        return ""

def grab_banner(ip: str, port: int) -> Tuple[str, Optional[TLSInfo]]:
    if port in TLS_PORTS:
        return grab_tls(ip, port)
    return grab_plain(ip, port), None

# ============================================================================
# GEO / ASN
# ============================================================================
class GeoDB:
    def __init__(self):
        self._mmdb = None
        self._s: List[int] = []; self._e: List[int] = []; self._r: List[Tuple] = []
        if GEOIP_DB and os.path.exists(GEOIP_DB):
            try:
                import geoip2.database
                self._mmdb = geoip2.database.Reader(GEOIP_DB)
            except Exception as e: log.warning("mmdb: %s", e)
        if ASN_CSV and os.path.exists(ASN_CSV):
            try:
                rows = []
                for line in open(ASN_CSV):
                    p = line.strip().split(",")
                    if len(p) < 6: continue
                    try: rows.append((int(p[0]), int(p[1]), p[2].upper(),
                                     p[3], p[4], int(p[5])))
                    except Exception: continue
                rows.sort()
                self._r = rows
                self._s = [r[0] for r in rows]
                self._e = [r[1] for r in rows]
                log.info("geo CSV: %d ranges", len(rows))
            except Exception as e: log.warning("geo CSV: %s", e)

    def lookup(self, ip: str) -> Geo:
        g = Geo()
        if self._mmdb:
            try:
                r = self._mmdb.city(ip)
                g.country, g.country_code = r.country.name, r.country.iso_code
                g.city = r.city.name
                g.latitude, g.longitude = r.location.latitude, r.location.longitude
            except Exception: pass
        if self._r:
            n = int(ipaddress.ip_address(ip))
            i = bisect.bisect_right(self._s, n) - 1
            if i >= 0 and n <= self._e[i]:
                r = self._r[i]
                g.country_code = r[2] or g.country_code
                g.country      = r[3] or g.country
                g.org          = r[4] or g.org
                g.asn          = r[5] or g.asn
        return g

GEO: Optional[GeoDB] = None

# ============================================================================
# ONLINE FEED SYNC — NVD + CISA KEV + EPSS
# ============================================================================
def _download(url: str, dest: str, timeout: int = 180) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CyberScan/3.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
            while True:
                ch = r.read(1 << 20)
                if not ch: break
                f.write(ch)
        return True
    except Exception as e:
        log.error("download %s: %s", url, e)
        return False

def _open_json_auto(path: str):
    if path.endswith(".xz"): return lzma.open(path, "rt", encoding="utf-8")
    if path.endswith(".gz"): return gzip.open(path, "rt", encoding="utf-8")
    return open(path, "r", encoding="utf-8")

def _cpe_parts(cpe: str) -> Optional[Tuple[str, str]]:
    if not cpe or not cpe.startswith("cpe:2.3:"): return None
    p = cpe.split(":")
    if len(p) < 5: return None
    return (p[3].lower().replace("\\", ""), p[4].lower().replace("\\", ""))

def _cvss_from_nvd(cve: dict) -> float:
    m = cve.get("metrics", {})
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        a = m.get(k) or []
        if a:
            try: return float(a[0]["cvssData"]["baseScore"])
            except Exception: continue
    return 0.0

def _parse_nvd_year(path: str) -> List[Tuple]:
    rows = []
    try:
        with _open_json_auto(path) as f:
            data = json.load(f)
    except Exception as e:
        log.warning("parse %s: %s", path, e); return rows
    # NVD_FEED_BASE serves the fkie-cad mirror, which flattens the official
    # NVD 2.0 shape: the list is "cve_items" and each item IS the CVE object.
    # Fall back to {"vulnerabilities":[{"cve":{...}}]} for the upstream API.
    for item in data.get("cve_items") or data.get("vulnerabilities") or []:
        cve = item.get("cve", item)
        cve_id = cve.get("id", "")
        if not cve_id: continue
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en": desc = d.get("value", ""); break
        cvss = _cvss_from_nvd(cve)
        seen = set()
        for cfg in cve.get("configurations", []) or []:
            for node in cfg.get("nodes", []) or []:
                for cm in node.get("cpeMatch", []) or []:
                    vp = _cpe_parts(cm.get("criteria", ""))
                    if not vp: continue
                    v, p = vp
                    key = (v, p, cm.get("versionStartIncluding"),
                           cm.get("versionStartExcluding"),
                           cm.get("versionEndIncluding"),
                           cm.get("versionEndExcluding"))
                    if key in seen: continue
                    seen.add(key)
                    rows.append((cve_id, v, p,
                                 cm.get("versionStartIncluding"),
                                 cm.get("versionStartExcluding"),
                                 cm.get("versionEndIncluding"),
                                 cm.get("versionEndExcluding"),
                                 cvss, desc[:500]))
    return rows

def sync_nvd(years: List[int], force: bool) -> None:
    os.makedirs(NVD_CACHE_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DROP TABLE IF EXISTS cve")
    conn.execute("""CREATE TABLE cve (
        cve_id TEXT, vendor TEXT, product TEXT,
        version_start_incl TEXT, version_start_excl TEXT,
        version_end_incl TEXT, version_end_excl TEXT,
        cvss REAL, description TEXT)""")
    conn.execute("CREATE INDEX idx_cve_prod ON cve(product)")
    conn.execute("CREATE INDEX idx_cve_vend ON cve(vendor)")
    all_rows = []
    for y in years:
        url  = f"{NVD_FEED_BASE}/CVE-{y}.json.xz"
        dest = os.path.join(NVD_CACHE_DIR, f"CVE-{y}.json.xz")
        if force or not os.path.exists(dest) or \
           (time.time() - os.path.getmtime(dest)) > 86400:
            log.info("downloading %s", url)
            if not _download(url, dest): continue
        else:
            log.info("using cached %s", dest)
        all_rows.extend(_parse_nvd_year(dest))
    if all_rows:
        conn.executemany("INSERT INTO cve VALUES (?,?,?,?,?,?,?,?,?)", all_rows)
        conn.commit()
    n = conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
    log.info("cve table: %d rows", n)
    conn.close()

def sync_kev() -> None:
    os.makedirs(NVD_CACHE_DIR, exist_ok=True)
    dest = os.path.join(NVD_CACHE_DIR, "kev.json")
    if not os.path.exists(dest) or (time.time() - os.path.getmtime(dest)) > 86400:
        log.info("downloading CISA KEV")
        if not _download(KEV_URL, dest): return
    with open(dest) as f: data = json.load(f)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DROP TABLE IF EXISTS kev")
    conn.execute("""CREATE TABLE kev (
        cve_id TEXT PRIMARY KEY, vendor TEXT, product TEXT,
        name TEXT, date_added TEXT, short_desc TEXT)""")
    rows = [(v.get("cveID",""), v.get("vendorProject",""), v.get("product",""),
             v.get("vulnerabilityName",""), v.get("dateAdded",""),
             (v.get("shortDescription","") or "")[:500])
            for v in data.get("vulnerabilities", [])]
    conn.executemany("INSERT OR IGNORE INTO kev VALUES (?,?,?,?,?,?)", rows)
    conn.commit()
    log.info("KEV synced: %d entries", len(rows))
    conn.close()

def sync_epss() -> None:
    os.makedirs(NVD_CACHE_DIR, exist_ok=True)
    dest = os.path.join(NVD_CACHE_DIR, "epss.csv.gz")
    if not os.path.exists(dest) or (time.time() - os.path.getmtime(dest)) > 86400:
        log.info("downloading EPSS")
        if not _download(EPSS_URL, dest): return
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DROP TABLE IF EXISTS epss")
    conn.execute("CREATE TABLE epss (cve_id TEXT PRIMARY KEY, score REAL, percentile REAL)")
    rows = []
    with gzip.open(dest, "rt", encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip(): continue
            parts = line.strip().split(",")
            if len(parts) < 3 or parts[0].lower() == "cve": continue
            try: rows.append((parts[0], float(parts[1]), float(parts[2])))
            except ValueError: continue
    conn.executemany("INSERT OR IGNORE INTO epss VALUES (?,?,?)", rows)
    conn.commit()
    log.info("EPSS synced: %d entries", len(rows))
    conn.close()

# ============================================================================
# CVE MATCHER
# ============================================================================
def _vtuple(v: str) -> Tuple:
    out = []
    for p in re.split(r"[.\-_]", v or ""):
        m = re.match(r"(\d+)", p)
        out.append(int(m.group(1)) if m else 0)
    return tuple(out)

def _vrange(ver, si, se, ei, ee) -> bool:
    if not ver: return False
    v = _vtuple(ver)
    if si and v < _vtuple(si): return False
    if se and v <= _vtuple(se): return False
    if ei and v > _vtuple(ei): return False
    if ee and v >= _vtuple(ee): return False
    return True

class CveDB:
    def __init__(self):
        self.rows: List[Tuple] = []
        self._by_product: Dict[str, List[int]] = {}
        self.kev: set = set()
        self.epss: Dict[str, float] = {}
        try:
            conn = sqlite3.connect(DB_PATH)
            self.rows = conn.execute(
                "SELECT cve_id, vendor, product, version_start_incl,"
                " version_start_excl, version_end_incl, version_end_excl,"
                " cvss FROM cve").fetchall()
            try:
                self.kev = {r[0] for r in conn.execute("SELECT cve_id FROM kev")}
            except sqlite3.OperationalError: pass
            try:
                self.epss = {r[0]: r[1] for r in conn.execute(
                    "SELECT cve_id, score FROM epss")}
            except sqlite3.OperationalError: pass
            conn.close()
        except Exception as e:
            log.warning("CveDB: %s (run `sync-feeds`)", e); return
        for i, r in enumerate(self.rows):
            self._by_product.setdefault(r[2], []).append(i)
        log.info("CveDB: %d CVE rows, %d products, %d KEV, %d EPSS",
                 len(self.rows), len(self._by_product), len(self.kev), len(self.epss))

    def match(self, svc: Service) -> Tuple[List[str], List[str], float, float]:
        blob = " ".join([(svc.product or "").lower(),
                         " ".join(svc.cpe).lower(),
                         svc.service_name.lower()])
        cand = set()
        for tok in set(re.split(r"[\s/,:]+", blob)):
            if tok in self._by_product:
                cand.update(self._by_product[tok])
        if not cand:
            for i, r in enumerate(self.rows):
                if r[2] and r[2] in blob: cand.add(i)
        hits, kev_hits = set(), []
        cvss, epss = 0.0, 0.0
        for i in cand:
            r = self.rows[i]
            if (r[3] or r[4] or r[5] or r[6]) and \
               not _vrange(svc.version, r[3], r[4], r[5], r[6]):
                continue
            hits.add(r[0])
            cvss = max(cvss, float(r[7] or 0))
            if r[0] in self.kev: kev_hits.append(r[0])
            if r[0] in self.epss: epss = max(epss, self.epss[r[0]])
        return sorted(hits), sorted(set(kev_hits)), cvss, epss

CVE: Optional[CveDB] = None

# ============================================================================
# STORAGE
# ============================================================================
SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT NOT NULL, port INTEGER NOT NULL, ip_int INTEGER NOT NULL,
    protocol TEXT, banner TEXT, service_name TEXT, product TEXT, version TEXT,
    extrainfo TEXT, cpe TEXT, os TEXT, http_title TEXT, http_server TEXT,
    tls_json TEXT, geo_json TEXT, cves TEXT, kev TEXT, cvss_max REAL,
    epss_max REAL, first_seen TEXT, last_seen TEXT,
    scan_round INTEGER, next_scan TEXT,
    PRIMARY KEY (ip, port)
);
CREATE INDEX IF NOT EXISTS idx_ipint    ON hosts(ip_int);
CREATE INDEX IF NOT EXISTS idx_port     ON hosts(port);
CREATE INDEX IF NOT EXISTS idx_product  ON hosts(product);
CREATE INDEX IF NOT EXISTS idx_nextscan ON hosts(next_scan);

CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT, port INTEGER, scan_round INTEGER, seen_at TEXT, record_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_obs_ip   ON observations(ip, port);
CREATE INDEX IF NOT EXISTS idx_obs_round ON observations(scan_round);

CREATE TABLE IF NOT EXISTS scan_rounds (
    round_id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT, finished_at TEXT, target TEXT, ports TEXT,
    total_found INTEGER
);
"""

FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS hosts_fts USING fts5(
    ip, port, banner, product, version, service_name, extrainfo,
    http_title, http_server,
    content='hosts', content_rowid='rowid'
);
CREATE TRIGGER IF NOT EXISTS hosts_ai AFTER INSERT ON hosts BEGIN
  INSERT INTO hosts_fts(rowid, ip, port, banner, product, version,
                        service_name, extrainfo, http_title, http_server)
  VALUES (new.rowid, new.ip, new.port, new.banner, new.product, new.version,
          new.service_name, new.extrainfo, new.http_title, new.http_server);
END;
CREATE TRIGGER IF NOT EXISTS hosts_ad AFTER DELETE ON hosts BEGIN
  INSERT INTO hosts_fts(hosts_fts, rowid, ip, port, banner, product, version,
                        service_name, extrainfo, http_title, http_server)
  VALUES ('delete', old.rowid, old.ip, old.port, old.banner, old.product,
          old.version, old.service_name, old.extrainfo, old.http_title, old.http_server);
END;
CREATE TRIGGER IF NOT EXISTS hosts_au AFTER UPDATE ON hosts BEGIN
  INSERT INTO hosts_fts(hosts_fts, rowid, ip, port, banner, product, version,
                        service_name, extrainfo, http_title, http_server)
  VALUES ('delete', old.rowid, old.ip, old.port, old.banner, old.product,
          old.version, old.service_name, old.extrainfo, old.http_title, old.http_server);
  INSERT INTO hosts_fts(rowid, ip, port, banner, product, version,
                        service_name, extrainfo, http_title, http_server)
  VALUES (new.rowid, new.ip, new.port, new.banner, new.product, new.version,
          new.service_name, new.extrainfo, new.http_title, new.http_server);
END;
"""

FTS_OK = False

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    global FTS_OK
    conn = db()
    conn.executescript(SCHEMA)
    try:
        conn.executescript(FTS_SCHEMA)
        FTS_OK = True
        log.info("FTS5 enabled")
    except sqlite3.OperationalError as e:
        log.warning("FTS5 unavailable — full-text search disabled (%s)", e)
    conn.commit()
    migrate_schema(conn)          # additive: new columns/tables for the intel layer
    conn.close()
    log.info("DB initialized: %s", DB_PATH)

def start_round(target: str, ports: List[int]) -> int:
    conn = db()
    cur = conn.execute(
        "INSERT INTO scan_rounds (started_at, target, ports, total_found)"
        " VALUES (?, ?, ?, 0)",
        (datetime.now(timezone.utc).isoformat(), target, ",".join(map(str, ports))))
    conn.commit(); rid = cur.lastrowid; conn.close()
    return rid

def finish_round(rid: int, found: int):
    conn = db()
    conn.execute("UPDATE scan_rounds SET finished_at=?, total_found=? WHERE round_id=?",
                 (datetime.now(timezone.utc).isoformat(), found, rid))
    conn.commit(); conn.close()

def _next_scan_for(port: int) -> str:
    days = 7 if port in HOT_PORTS else 30 if port in TOP_PORTS else 90
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()

def store_service(svc: Service):
    now = datetime.now(timezone.utc).isoformat()
    svc.last_seen = now
    conn = db()
    row = conn.execute("SELECT first_seen FROM hosts WHERE ip=? AND port=?",
                       (svc.ip, svc.port)).fetchone()
    svc.first_seen = row[0] if row else now
    # how many ports this IP already exposes — feeds the risk score
    try:
        open_ports = conn.execute(
            "SELECT COUNT(*) FROM hosts WHERE ip=?", (svc.ip,)).fetchone()[0] or 1
    except sqlite3.Error:
        open_ports = 1

    tls_blob = json.dumps(asdict(svc.tls), default=str) if svc.tls else None
    geo_blob = json.dumps(asdict(svc.geo), default=str) if svc.geo else None
    if not svc.risk_score:
        svc.risk_score = compute_risk_score({
            "cvss_max": svc.cvss_max, "epss_max": svc.epss_max,
            "kev": ",".join(svc.kev), "service_name": svc.service_name,
            "port": svc.port, "tls_json": tls_blob, "first_seen": svc.first_seen,
        }, open_ports)

    conn.execute("""
        INSERT INTO hosts (ip, port, ip_int, protocol, banner, service_name,
            product, version, extrainfo, cpe, os, http_title, http_server,
            tls_json, geo_json, cves, kev, cvss_max, epss_max,
            first_seen, last_seen, scan_round, next_scan,
            risk_score, techs, hostname, domain, tags, icon_hash, jarm, hassh,
            ja3s, http_status, http_headers, waf, cloud_provider)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,
                ?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(ip, port) DO UPDATE SET
            protocol=excluded.protocol, banner=excluded.banner,
            service_name=excluded.service_name, product=excluded.product,
            version=excluded.version, extrainfo=excluded.extrainfo,
            cpe=excluded.cpe, os=excluded.os,
            http_title=excluded.http_title, http_server=excluded.http_server,
            tls_json=excluded.tls_json, geo_json=excluded.geo_json,
            cves=excluded.cves, kev=excluded.kev,
            cvss_max=excluded.cvss_max, epss_max=excluded.epss_max,
            last_seen=excluded.last_seen, scan_round=excluded.scan_round,
            next_scan=excluded.next_scan,
            risk_score=excluded.risk_score, techs=excluded.techs,
            hostname=excluded.hostname, domain=excluded.domain,
            icon_hash=excluded.icon_hash,
            jarm=excluded.jarm, hassh=excluded.hassh, ja3s=excluded.ja3s,
            http_status=excluded.http_status, http_headers=excluded.http_headers,
            waf=excluded.waf, cloud_provider=excluded.cloud_provider
    """, (
        svc.ip, svc.port, int(ipaddress.ip_address(svc.ip)),
        svc.protocol, svc.banner, svc.service_name, svc.product, svc.version,
        svc.extrainfo, json.dumps(svc.cpe), svc.os,
        svc.http_title, svc.http_server,
        tls_blob, geo_blob,
        ",".join(svc.cves), ",".join(svc.kev),
        svc.cvss_max, svc.epss_max, svc.first_seen, svc.last_seen,
        svc.scan_round, _next_scan_for(svc.port),
        svc.risk_score, json.dumps(svc.techs), svc.hostname, svc.domain,
        svc.tags, svc.icon_hash, svc.jarm, svc.hassh, svc.ja3s,
        svc.http_status, svc.http_headers, svc.waf, svc.cloud_provider))
    conn.execute(
        "INSERT INTO observations (ip, port, scan_round, seen_at, record_json)"
        " VALUES (?,?,?,?,?)",
        (svc.ip, svc.port, svc.scan_round, now, svc.to_json()))
    # Sync auto-tags into host_tags (delete stale, insert current)
    if svc.tags is not None:
        conn.execute("DELETE FROM host_tags WHERE ip=? AND port=?", (svc.ip, svc.port))
        for tag in [t for t in svc.tags.split(",") if t]:
            conn.execute(
                "INSERT OR IGNORE INTO host_tags (ip, port, tag) VALUES (?,?,?)",
                (svc.ip, svc.port, tag))
    conn.commit(); conn.close()


def store_pci_findings(svc, findings: list) -> int:
    """
    Persist CardFinding list for a host into pci_findings.
    Uses INSERT OR IGNORE so duplicate (ip, port, masked_pan) rows are silently skipped.
    Returns the number of new rows inserted.
    """
    if not findings:
        return 0
    now = datetime.now(timezone.utc).isoformat()
    conn = db()
    inserted = 0
    try:
        for f in findings:
            cur = conn.execute(
                """INSERT OR IGNORE INTO pci_findings
                   (ip, port, service_name, detected_at, card_network, luhn_valid,
                    masked_pan, bin_prefix, issuer, country, funding_type)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (svc.ip, svc.port, svc.service_name or "", now,
                 f.card_network, int(f.luhn_valid), f.masked_pan,
                 f.bin_prefix, f.issuer, f.country, f.funding_type))
            inserted += cur.rowcount
        conn.commit()
    except sqlite3.Error as exc:
        log.warning("store_pci_findings %s:%s — %s", svc.ip, svc.port, exc)
    finally:
        conn.close()
    return inserted


# ============================================================================
# SCANNER
# ============================================================================
def load_allowlist() -> List[ipaddress._BaseNetwork]:
    nets = []
    if not os.path.exists(ALLOWLIST_FILE):
        log.error("No allowlist file: %s", ALLOWLIST_FILE); return nets
    for line in Path(ALLOWLIST_FILE).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        try: nets.append(ipaddress.ip_network(line, strict=False))
        except ValueError as e: log.warning("bad CIDR %s: %s", line, e)
    return nets

def allowed(ip, nets) -> bool:
    a = ipaddress.ip_address(ip)
    return any(a in n for n in nets if n.version == a.version)

async def _probe(ip, port, sem):
    async with sem:
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=TIMEOUT)
            w.close()
            try: await w.wait_closed()
            except Exception: pass
            return True
        except Exception: return False

async def probe_targets(targets):
    """Connect-scan (ip, port) pairs and return the ones that answer.

    Takes any iterable and consumes it a batch at a time: a /8 is 33M pairs
    across the top ports, which must never be built as a list first.
    """
    sem = asyncio.Semaphore(CONCURRENCY)
    it = iter(targets)
    found, BATCH = [], 4096
    while True:
        chunk = list(itertools.islice(it, BATCH))
        if not chunk:
            return found
        rs = await asyncio.gather(*[_probe(ip, p, sem) for ip, p in chunk])
        found.extend([(ip, p) for (ip, p), ok in zip(chunk, rs) if ok])

async def discover_asyncio(cidr, ports, nets):
    net = ipaddress.ip_network(cidr)
    size = net.num_addresses * max(1, len(ports))
    if size > 1 << 16:
        log.warning("%s × %d ports = %s probes — at ~%d in flight this is a long "
                    "sweep; masscan handles ranges this size far faster",
                    cidr, len(ports), f"{size:,}", CONCURRENCY)
    return await probe_targets(
        (str(ip), p) for ip in net.hosts() if allowed(str(ip), nets) for p in ports)

def discover_masscan(cidr, ports, nets, wait: int = 2, rate: int = 0):
    """SYN-scan cidr:ports via masscan. Returns (ip, port) list, raises on binary error."""
    rate = rate or RATE_PPS
    try:
        r = subprocess.run([MASSCAN, "--version"], capture_output=True, timeout=5)
        if r.returncode != 0:
            raise RuntimeError("masscan --version non-zero")
    except Exception as exc:
        raise RuntimeError(f"masscan unavailable: {exc}") from exc
    cmd = [MASSCAN, cidr, "-p", ",".join(map(str, ports)),
           "--rate", str(rate), "-oL", "-", "--wait", str(wait)]
    log.info("masscan: %s", " ".join(cmd))
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=600).stdout
    except Exception as e:
        raise RuntimeError(f"masscan run failed: {e}") from e
    found = []
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 4 and p[0] == "open":
            ip, port = p[3], int(p[2])
            if allowed(ip, nets): found.append((ip, port))
    return found

async def enrich_and_store(ip: str, port: int, round_id: int):
    banner, tls = await asyncio.to_thread(grab_banner, ip, port)
    fp = fingerprint(banner, port)
    svc = Service(ip=ip, port=port, banner=banner[:8192],
                  tls=tls, scan_round=round_id, **{k: fp[k] for k in
                  ("service_name","product","version","extrainfo",
                   "http_title","http_server","cpe")})
    if GEO: svc.geo = GEO.lookup(ip)
    if CVE:
        svc.cves, svc.kev, svc.cvss_max, svc.epss_max = CVE.match(svc)

    # ── intelligence enrichment ────────────────────────────────────────────
    headers_str = fp.get("http_headers") or ""
    svc.http_headers = headers_str[:4000]
    try:
        svc.http_status = int(fp.get("http_status") or 0)
    except (TypeError, ValueError):
        svc.http_status = 0

    # PTR lookup, every alias, and the registrable domain behind each name.
    # Everything found is written to the hostnames table by the resolver.
    dns = await asyncio.to_thread(resolve_host_dns, ip)
    svc.hostname = dns.get("hostname", "")
    svc.domain = dns.get("domain", "")
    svc.techs = tech_names(detect_technologies(
        banner=svc.banner, body=svc.banner, headers=headers_str))
    svc.waf = detect_waf(headers_str, svc.banner)
    svc.cloud_provider = detect_cloud(
        ip, (svc.geo.org if svc.geo else ""), svc.banner)
    svc.tags = compute_auto_tags(
        port, svc.service_name, svc.product,
        svc.banner, svc.http_title, headers_str)

    if port in (22, 2222):
        _ssh_banner, kex = await asyncio.to_thread(grab_ssh_kex, ip, port)
        svc.hassh = compute_hassh(_ssh_banner, kex)
    if svc.tls is not None:
        svc.jarm = await asyncio.to_thread(jarm_fingerprint, ip, port)
    if port in (80, 443, 8080, 8443) and svc.service_name in ("http", "https", ""):
        scheme = "https" if port in (443, 8443) or svc.tls else "http"
        svc.icon_hash = await asyncio.to_thread(
            fetch_icon_hash, f"{scheme}://{ip}:{port}")

    await asyncio.to_thread(store_service, svc)

    # PCI banner scan — offline, zero-latency, never retains full PANs
    if _cd_scan_banner is not None and svc.banner:
        try:
            _findings = _cd_scan_banner(svc.banner)
            if _findings:
                await asyncio.to_thread(store_pci_findings, svc, _findings)
                log.info("pci: %s:%s — %d candidate(s) stored", svc.ip, svc.port, len(_findings))
        except Exception as _exc:
            log.debug("pci scan error %s:%s — %s", svc.ip, svc.port, _exc)

    return svc

async def scan_cycle(cidr, ports, nets, expand_dns: bool = True) -> int:
    t0 = time.time()
    found = discover_masscan(cidr, ports, nets)
    if not found:
        found = await discover_asyncio(cidr, ports, nets)
    rid = start_round(cidr, ports)
    log.info("[%s] %d open ports — enriching", cidr, len(found))
    sem = asyncio.Semaphore(max(8, CONCURRENCY // 4))
    names: set = set()

    async def _w(ip, port):
        async with sem:
            svc = await enrich_and_store(ip, port, rid)
            if svc:
                for n in (svc.hostname, svc.domain):
                    if n:
                        names.add(n)

    await asyncio.gather(*[_w(ip, p) for ip, p in found])
    total = len(found)

    # ── DNS expansion ──────────────────────────────────────────────────────
    # Reverse DNS told us which names live on this range. Resolving those
    # names forward often points at addresses the sweep never reached (a
    # second A record, a different subnet). Any such address that the
    # allowlist ALREADY authorises joins this same round; anything outside
    # the allowlist is dropped, so DNS can never widen the scan's scope.
    if expand_dns and names:
        seen = {ip for ip, _ in found}
        new_ips = await asyncio.to_thread(dns_expand, sorted(names), nets, seen)
        if new_ips:
            log.info("[%s] DNS expansion: %d authorised address(es) — %s",
                     cidr, len(new_ips), ", ".join(new_ips[:6]))
            hits = await probe_targets([(ip, p) for ip in new_ips for p in ports])
            await asyncio.gather(*[_w(ip, p) for ip, p in hits])
            total += len(hits)

    finish_round(rid, total)
    log.info("[%s] round %d — %d services in %.1fs",
             cidr, rid, total, time.time() - t0)
    return rid

# ============================================================================
# QUERY LANGUAGE + FTS + FACETS
# ============================================================================
# Columns a bare "key:value" token may filter on. The key is interpolated
# straight into the SQL below, so anything not on this list must never reach
# it — an unknown key was both a 500 ("no such column") and an injection hole.
_HOST_COLUMNS = {
    "ip", "port", "protocol", "banner", "service_name", "product", "version",
    "extrainfo", "cpe", "os", "http_title", "http_server", "tls_json",
    "geo_json", "cves", "kev", "cvss_max", "epss_max", "first_seen",
    "last_seen", "scan_round",
    # intelligence layer columns
    "risk_score", "techs", "hostname", "domain", "tags", "icon_hash", "jarm",
    "hassh", "ja3s", "http_status", "http_headers", "waf", "cloud_provider",
}
# the UI advertises cve:CVE-2024, but the column is "cves"
_HOST_COLUMN_ALIASES = {"cve": "cves"}


def parse_query(q: str) -> Tuple[str, List[Any]]:
    parts, params = [], []
    for tok in shlex.split(q):
        if tok == "*":
            # bare wildcard: match everything, so run_query("*") and the
            # web API's "*" shortcut agree instead of searching for a literal
            continue
        if ":" in tok:
            k, v = tok.split(":", 1); k = k.lower()
            if k == "port":
                ports = [int(x) for x in v.split(",")]
                parts.append(f"port IN ({','.join(['?']*len(ports))})")
                params.extend(ports)
            elif k == "country":
                parts.append("json_extract(geo_json,'$.country_code') = ?")
                params.append(v.upper())
            elif k == "city":
                parts.append("json_extract(geo_json,'$.city') LIKE ?")
                params.append(f"%{v}%")
            elif k == "asn":
                parts.append("json_extract(geo_json,'$.asn') = ?")
                params.append(int(v))
            elif k == "org":
                parts.append("json_extract(geo_json,'$.org') LIKE ?")
                params.append(f"%{v}%")
            elif k == "product":
                parts.append("lower(product) LIKE ?"); params.append(f"%{v.lower()}%")
            elif k == "version":
                parts.append("version LIKE ?"); params.append(f"%{v}%")
            elif k == "service":
                parts.append("service_name = ?"); params.append(v.lower())
            elif k == "os":
                parts.append("lower(os) LIKE ?"); params.append(f"%{v.lower()}%")
            elif k == "vuln":
                parts.append("cves LIKE ?"); params.append(f"%{v.upper()}%")
            elif k == "kev":
                parts.append("kev != ''" if v.lower() in ("true","1","yes") else "kev = ''")
            elif k == "cvss":
                # parse before appending: the placeholder must not be added
                # unless the value is usable, or the "?" is left with no param
                try: _n = float(v)
                except ValueError: pass
                else: parts.append("cvss_max >= ?"); params.append(_n)
            elif k == "epss":
                try: _n = float(v)
                except ValueError: pass
                else: parts.append("epss_max >= ?"); params.append(_n)
            elif k == "cpe":
                parts.append("cpe LIKE ?"); params.append(f"%{v}%")
            elif k == "ip":
                net = ipaddress.ip_network(v, strict=False)
                parts.append("ip_int BETWEEN ? AND ?")
                params.extend([int(net.network_address), int(net.broadcast_address)])
            elif k == "banner":
                parts.append("banner LIKE ?"); params.append(f"%{v}%")
            elif k == "http.title":
                parts.append("lower(http_title) LIKE ?"); params.append(f"%{v.lower()}%")
            elif k == "http.server":
                parts.append("lower(http_server) LIKE ?"); params.append(f"%{v.lower()}%")
            elif k == "ssl.cn":
                parts.append("json_extract(tls_json,'$.subject_cn') LIKE ?")
                params.append(f"%{v}%")
            elif k == "ssl.issuer":
                parts.append("json_extract(tls_json,'$.issuer_cn') LIKE ?")
                params.append(f"%{v}%")
            elif k == "ssl.sha256":
                parts.append("json_extract(tls_json,'$.sha256') = ?"); params.append(v.lower())

            # ── NorthHarv intelligence operators ───────────────────────────
            elif k in ("tech", "app"):
                parts.append("lower(techs) LIKE ?"); params.append(f"%{v.lower()}%")
            elif k == "risk":
                try:
                    _n = float(v)
                except ValueError:
                    pass
                else:
                    parts.append("risk_score >= ?"); params.append(_n)
            elif k == "jarm":
                parts.append("jarm = ?"); params.append(v.lower())
            elif k in ("icon_hash", "favicon", "icon"):
                try:
                    _n = int(v)
                except ValueError:
                    pass
                else:
                    parts.append("icon_hash = ?"); params.append(_n)
            elif k in ("hassh", "ssh.hassh"):
                parts.append("hassh = ?"); params.append(v.lower())
            elif k in ("ssl.ja3s", "ja3s"):
                parts.append("ja3s = ?"); params.append(v.lower())
            elif k in ("http.body", "body"):
                parts.append("banner LIKE ?"); params.append(f"%{v}%")
            elif k == "http.status":
                try:
                    _n = int(v)
                except ValueError:
                    pass
                else:
                    parts.append("http_status = ?"); params.append(_n)
            elif k in ("http.waf", "waf"):
                parts.append("lower(waf) LIKE ?"); params.append(f"%{v.lower()}%")
            elif k in ("header", "http.headers"):
                parts.append("http_headers LIKE ?"); params.append(f"%{v}%")
            elif k in ("cloud", "cloud.provider"):
                parts.append("lower(cloud_provider) LIKE ?"); params.append(f"%{v.lower()}%")
            elif k in ("hostname", "host"):
                parts.append("lower(hostname) LIKE ?"); params.append(f"%{v.lower()}%")
            elif k == "domain":
                # the registrable domain is resolved and stored in its own
                # column, so this can match exactly instead of by substring —
                # and still catch every hostname sitting under that domain.
                parts.append("(lower(domain) = ? OR lower(hostname) LIKE ?)")
                params.append(v.lower()); params.append(f"%.{v.lower()}")
            elif k in ("ssl.san", "cert"):
                parts.append("tls_json LIKE ?"); params.append(f"%{v}%")
            elif k == "ssl.version":
                parts.append("json_extract(tls_json,'$.version') LIKE ?"); params.append(f"%{v}%")
            elif k == "ssl.alpn":
                parts.append("tls_json LIKE ?"); params.append(f"%{v}%")
            elif k == "ssl.expired":
                if v.lower() in ("true", "1", "yes"):
                    parts.append("CAST(json_extract(tls_json,'$.days_to_expiry') AS INTEGER) < 0")
                else:
                    parts.append("CAST(json_extract(tls_json,'$.days_to_expiry') AS INTEGER) >= 0")
            elif k in ("ssl.selfsigned", "ssl.self_signed"):
                want = 1 if v.lower() in ("true", "1", "yes") else 0
                parts.append("COALESCE(json_extract(tls_json,'$.self_signed'),0) = ?")
                params.append(want)
            elif k == "tag":
                parts.append("lower(tags) LIKE ?"); params.append(f"%{v.lower()}%")
            elif k == "title":
                parts.append("lower(http_title) LIKE ?"); params.append(f"%{v.lower()}%")
            elif k == "server":
                parts.append("lower(http_server) LIKE ?"); params.append(f"%{v.lower()}%")
            elif k == "net":
                try:
                    _net = ipaddress.ip_network(v, strict=False)
                except ValueError:
                    pass
                else:
                    parts.append("ip_int BETWEEN ? AND ?")
                    params.extend([int(_net.network_address), int(_net.broadcast_address)])
            elif k == "has":
                _what = v.lower()
                if _what == "tls":
                    parts.append("tls_json IS NOT NULL AND tls_json != ''")
                elif _what == "cve":
                    parts.append("cves != ''")
                elif _what == "kev":
                    parts.append("kev != ''")
                elif _what == "waf":
                    parts.append("waf != ''")
                elif _what in ("tech", "app"):
                    parts.append("techs NOT IN ('', '[]')")
                elif _what == "hostname":
                    parts.append("hostname != ''")
                elif _what == "domain":
                    parts.append("domain != ''")
                elif _what == "cloud":
                    parts.append("cloud_provider != ''")
                elif _what in ("screenshot", "ipv6"):
                    parts.append("1=0")        # not collected yet
                else:
                    parts.append("1=1")
            elif k == "port.count":
                try:
                    _n = int(v)
                except ValueError:
                    pass
                else:
                    parts.append(
                        "ip IN (SELECT ip FROM hosts GROUP BY ip HAVING COUNT(*) >= ?)")
                    params.append(_n)
            elif k == "before":
                parts.append("last_seen < ?"); params.append(v)
            elif k == "after":
                parts.append("last_seen > ?"); params.append(v)
            elif k == "age":
                try:
                    _n = int(v)
                except ValueError:
                    pass
                else:
                    parts.append(f"first_seen < datetime('now','-{_n} days')")
            elif k == "region":
                parts.append("json_extract(geo_json,'$.region') LIKE ?"); params.append(f"%{v}%")
            elif k == "isp":
                parts.append("json_extract(geo_json,'$.org') LIKE ?"); params.append(f"%{v}%")
            elif k == "geo":
                # geo:lat,lon,radius_km -> bounding box on the stored lat/lon
                bits = [b.strip() for b in v.split(",")]
                try:
                    lat, lon = float(bits[0]), float(bits[1])
                    radius = float(bits[2]) if len(bits) > 2 else 50.0
                except (ValueError, IndexError):
                    pass
                else:
                    dlat = radius / 111.0
                    dlon = radius / max(1e-6, 111.0 * math.cos(math.radians(lat)))
                    parts.append(
                        "CAST(json_extract(geo_json,'$.latitude') AS REAL) BETWEEN ? AND ?"
                        " AND CAST(json_extract(geo_json,'$.longitude') AS REAL) BETWEEN ? AND ?")
                    params.extend([lat - dlat, lat + dlat, lon - dlon, lon + dlon])
            else:
                col = _HOST_COLUMN_ALIASES.get(k, k)
                if col in _HOST_COLUMNS:
                    parts.append(f"{col} LIKE ?"); params.append(f"%{v}%")
                else:
                    # unrecognised field — match the whole token as free text
                    # rather than letting it become a column name
                    parts.append("(banner LIKE ? OR product LIKE ? OR version LIKE ?)")
                    params.extend([f"%{tok}%"] * 3)
        else:
            parts.append("(banner LIKE ? OR product LIKE ? OR version LIKE ?)")
            params.extend([f"%{tok}%"] * 3)
    return (" AND ".join(parts) if parts else "1=1"), params

def run_query(q: str, limit: int = 50) -> List[Dict[str, Any]]:
    where, params = parse_query(q)
    conn = db(); conn.row_factory = sqlite3.Row
    rows = conn.execute(
        f"SELECT * FROM hosts WHERE {where} "
        f"ORDER BY kev DESC, cvss_max DESC, epss_max DESC, last_seen DESC "
        f"LIMIT {int(limit)}", params).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def run_fts(q: str, limit: int = 50) -> List[Dict[str, Any]]:
    if not FTS_OK: return []
    conn = db(); conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            f"SELECT h.* FROM hosts_fts f JOIN hosts h ON h.rowid = f.rowid "
            f"WHERE hosts_fts MATCH ? LIMIT {int(limit)}", (q,)).fetchall()
    except sqlite3.OperationalError:
        rows = []
    conn.close()
    return [dict(r) for r in rows]

def run_facets(q: str, field: str, limit: int = 20) -> List[Tuple[str, int]]:
    where, params = parse_query(q)
    conn = db()
    # allowlist only: `field` comes from the caller and is interpolated into
    # the SQL, so an unknown name must never reach it
    field_sql = {
        "port":         "CAST(port AS TEXT)",
        "country":      "json_extract(geo_json,'$.country_code')",
        "city":         "json_extract(geo_json,'$.city')",
        "region":       "json_extract(geo_json,'$.region')",
        "product":      "product",
        "version":      "version",
        "service":      "service_name",
        "asn":          "CAST(json_extract(geo_json,'$.asn') AS TEXT)",
        "org":          "json_extract(geo_json,'$.org')",
        "os":           "os",
        "http.server":  "http_server",
        "ssl.issuer":   "json_extract(tls_json,'$.issuer_cn')",
        "ssl.version":  "json_extract(tls_json,'$.version')",
        "cve":          "cves",
        "cloud":        "cloud_provider",
        "waf":          "waf",
        "tag":          "tags",
        "hostname":     "hostname",
        "domain":       "domain",
        "severity":     ("CASE WHEN cvss_max>=9 THEN 'CRITICAL'"
                         " WHEN cvss_max>=7 THEN 'HIGH'"
                         " WHEN cvss_max>=4 THEN 'MEDIUM'"
                         " WHEN cvss_max>0 THEN 'LOW' ELSE 'NONE' END"),
        "risk":         ("CASE WHEN risk_score>=800 THEN 'CRITICAL'"
                         " WHEN risk_score>=600 THEN 'HIGH'"
                         " WHEN risk_score>=350 THEN 'MEDIUM'"
                         " WHEN risk_score>=150 THEN 'LOW' ELSE 'MINIMAL' END"),
    }.get(field)
    if field_sql is None:
        conn.close()
        return []
    try:
        rows = conn.execute(
            f"SELECT {field_sql} k, COUNT(*) c FROM hosts WHERE {where} "
            f"GROUP BY k HAVING k IS NOT NULL AND k != '' "
            f"ORDER BY c DESC LIMIT {int(limit)}", params).fetchall()
    except sqlite3.OperationalError:
        rows = []
    conn.close()
    return [(str(k), c) for k, c in rows]

def print_rows(rows: List[Dict]):
    if not rows:
        print("(no results)"); return
    print(f"{'IP':<16} {'PORT':<6} {'SERVICE':<12} {'PRODUCT/VERSION':<28}"
          f" {'GEO':<18} {'CVSS':<5} {'EPSS':<5} {'KEV':<4} {'CVEs':<22}")
    print("-" * 130)
    for r in rows:
        geo = json.loads(r["geo_json"] or "{}")
        loc = f"{geo.get('country_code') or '?'}/{(geo.get('org') or '?')[:12]}"
        prod = f"{r['product'] or ''} {r['version'] or ''}".strip() or r["service_name"]
        cves = (r["cves"] or "")[:20]
        kev = "Y" if r.get("kev") else "-"
        print(f"{r['ip']:<16} {r['port']:<6} {(r['service_name'] or '')[:12]:<12}"
              f" {prod[:28]:<28} {loc[:18]:<18} {r['cvss_max']:<5.1f}"
              f" {r['epss_max']:<5.3f} {kev:<4} {cves:<22}")

def print_facets(facets: Dict[str, List[Tuple[str,int]]]):
    for field, items in facets.items():
        print(f"\n── {field} ──")
        for k, c in items:
            print(f"  {k:<40} {c}")

# ============================================================================
# DIFF
# ============================================================================
def diff_rounds(a: int, b: int):
    conn = db()
    a_rows = conn.execute(
        "SELECT ip, port, record_json FROM observations WHERE scan_round=? "
        "GROUP BY ip, port HAVING MAX(seen_at)", (a,)).fetchall()
    b_rows = conn.execute(
        "SELECT ip, port, record_json FROM observations WHERE scan_round=? "
        "GROUP BY ip, port HAVING MAX(seen_at)", (b,)).fetchall()
    conn.close()
    A = {(r[0], r[1]): json.loads(r[2]) for r in a_rows}
    B = {(r[0], r[1]): json.loads(r[2]) for r in b_rows}
    appeared = set(B) - set(A)
    disappeared = set(A) - set(B)
    changed = []
    for k in set(A) & set(B):
        pa, pb = A[k], B[k]
        diffs = [f for f in ("product","version","cves","http_title",
                             "http_server","service_name")
                 if (pa.get(f) or "") != (pb.get(f) or "")]
        if diffs: changed.append((k, diffs, pa, pb))

    print(f"Round {a} → {b}")
    print(f"  Appeared:    {len(appeared)}")
    print(f"  Disappeared: {len(disappeared)}")
    print(f"  Changed:     {len(changed)}")
    if appeared:
        print("\n── Appeared ──")
        for ip, p in sorted(appeared)[:50]:
            r = B[(ip, p)]
            print(f"  {ip:<16}:{p:<6} {r.get('product','')} {r.get('version','')}")
    if disappeared:
        print("\n── Disappeared ──")
        for ip, p in sorted(disappeared)[:50]:
            r = A[(ip, p)]
            print(f"  {ip:<16}:{p:<6} {r.get('product','')} {r.get('version','')}")
    if changed:
        print("\n── Changed ──")
        for (ip, p), flds, pa, pb in changed[:50]:
            print(f"  {ip:<16}:{p:<6} fields={','.join(flds)}")
            for f in flds:
                print(f"      {f}: {pa.get(f) or ''!r} → {pb.get(f) or ''!r}")

# ============================================================================
# DAEMON
# ============================================================================
DAEMON_HEARTBEAT   = 15      # seconds between liveness writes
DAEMON_STALE_AFTER = 75      # no heartbeat for this long ⇒ not running
ALLOWLIST_RETRY    = 60      # re-read an empty allowlist this often


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


_DAEMON_FIELDS = {
    "status", "pid", "interval_seconds", "started_at", "heartbeat_at",
    "cycle_started_at", "last_cycle_at", "next_scan_at", "cycles",
    "current_target", "targets", "ports", "last_found", "total_found",
    "last_error",
}


def _daemon_set(**fields) -> None:
    """Upsert the single daemon_state row. Never raises — state is telemetry."""
    fields.setdefault("heartbeat_at", _utc())
    # column names are interpolated below, so only known ones may get there
    cols = [c for c in fields if c in _DAEMON_FIELDS]
    if not cols:
        return
    try:
        conn = db()
        conn.execute(
            "INSERT INTO daemon_state (id, %s) VALUES (1, %s)"
            " ON CONFLICT(id) DO UPDATE SET %s" % (
                ", ".join(cols),
                ", ".join(["?"] * len(cols)),
                ", ".join(f"{c}=excluded.{c}" for c in cols)),
            [fields[c] for c in cols])
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        log.debug("daemon_state write failed: %s", e)


def daemon_status() -> Dict[str, Any]:
    """Current daemon state for the dashboard. Safe on an un-migrated DB."""
    row = None
    try:
        conn = db(); conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM daemon_state WHERE id = 1").fetchone()
        conn.close()
    except sqlite3.Error:
        pass
    if row is None:
        return {"status": "never_started", "running": False,
                "interval_seconds": 24 * 3600, "allowlist": len(load_allowlist())}

    st = {k: row[k] for k in row.keys()}
    now = datetime.now(timezone.utc)

    # A daemon is alive only if it wrote a heartbeat recently. Checking the
    # pid is not portable (os.kill with signal 0 terminates on Windows), so
    # the heartbeat is the single source of truth.
    age = None
    if st.get("heartbeat_at"):
        try:
            age = (now - datetime.fromisoformat(st["heartbeat_at"])).total_seconds()
        except (TypeError, ValueError):
            age = None
    st["heartbeat_age"] = age
    alive = st.get("status") in ("starting", "scanning", "sleeping", "waiting")
    st["running"] = bool(alive and age is not None and age < DAEMON_STALE_AFTER)
    if alive and not st["running"]:
        st["status"] = "stale"          # process died without cleaning up

    st["next_scan_in"] = None
    if st["running"] and st.get("next_scan_at"):
        try:
            st["next_scan_in"] = max(0, int(
                (datetime.fromisoformat(st["next_scan_at"]) - now).total_seconds()))
        except (TypeError, ValueError):
            pass
    st["allowlist"] = len(load_allowlist())
    return st


# ── Internet Crawl ────────────────────────────────────────────────────────────
# LCG with period 2^24: visits every possible /24 network exactly once per cycle.
# Hull-Dobell conditions satisfied: c odd, m=2^24 (power of 2), a≡1 (mod 4).
_CRAWL_LCG_M: int = 1 << 24          # 16,777,216
_CRAWL_LCG_A: int = 1_664_525
_CRAWL_LCG_C: int = 1_013_904_223

# RFC 5735 / RFC 1918 exclusions — never scan these /24s
_CRAWL_EXCLUDED_CIDRS = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
    "224.0.0.0/4", "240.0.0.0/4",
]
_crawl_excluded_cache: Optional[set] = None


def _crawl_excluded() -> set:
    global _crawl_excluded_cache
    if _crawl_excluded_cache is None:
        s: set = set()
        for cidr in _CRAWL_EXCLUDED_CIDRS:
            net = ipaddress.ip_network(cidr)
            for sub in net.subnets(new_prefix=24):
                # 24-bit network ID: top 3 octets
                s.add(int(sub.network_address) >> 8)
        _crawl_excluded_cache = s
    return _crawl_excluded_cache


def crawl_lcg_step(state: int) -> int:
    return (_CRAWL_LCG_A * state + _CRAWL_LCG_C) % _CRAWL_LCG_M


def crawl_lcg_to_cidr(state: int) -> Optional[str]:
    """Return the /24 CIDR for this LCG state, or None if excluded."""
    if state in _crawl_excluded():
        return None
    a = (state >> 16) & 0xFF
    b = (state >> 8) & 0xFF
    c = state & 0xFF
    return f"{a}.{b}.{c}.0/24"


def crawl_total_chunks() -> int:
    return _CRAWL_LCG_M - len(_crawl_excluded())


def crawl_load_state() -> Dict[str, Any]:
    try:
        conn = db()
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM crawl_state WHERE id=1").fetchone()
        conn.close()
        return dict(row) if row else {}
    except sqlite3.Error:
        return {}


def crawl_save_state(**kwargs) -> None:
    conn = db()
    try:
        exists = conn.execute("SELECT id FROM crawl_state WHERE id=1").fetchone()
        if exists:
            sets = ", ".join(f"{k}=?" for k in kwargs)
            conn.execute(f"UPDATE crawl_state SET {sets} WHERE id=?",
                         list(kwargs.values()) + [1])
        else:
            kwargs.setdefault("id", 1)
            cols = ", ".join(kwargs.keys())
            phs = ", ".join("?" * len(kwargs))
            conn.execute(f"INSERT INTO crawl_state ({cols}) VALUES ({phs})",
                         list(kwargs.values()))
        conn.commit()
    except sqlite3.Error as e:
        log.warning("crawl_save_state: %s", e)
    finally:
        conn.close()


def rescan_due(ports: List[int], nets) -> int:
    """Re-probe hosts whose next_scan has passed, in a scan round of their own.

    The per-port next_scan cadence (7/30/90 days) is what makes a hot port
    come back sooner than a quiet one. These re-probes used to be written
    with scan_round 0, which left them invisible to the timeline and the
    change feed — so they now get a real round like any other scan.
    """
    try:
        conn = db()
        due = conn.execute(
            "SELECT ip, port FROM hosts WHERE next_scan < ? LIMIT 10000",
            (_utc(),)).fetchall()
        conn.close()
    except sqlite3.Error as e:
        log.warning("due-host lookup failed: %s", e)
        return 0

    # A host recorded under an earlier, wider allowlist must not be touched
    # again unless the current allowlist still authorises it.
    due = [(ip, p) for ip, p in due if allowed(ip, nets)]
    if not due:
        return 0

    rid = start_round("due-rescan", ports)
    log.info("round %d — re-probing %d due host/port pairs", rid, len(due))

    async def _run():
        sem = asyncio.Semaphore(max(8, CONCURRENCY // 4))
        async def _w(ip, p):
            async with sem:
                try:
                    await enrich_and_store(ip, p, rid)
                except Exception as e:
                    log.debug("rescan %s:%s — %s", ip, p, e)
        await asyncio.gather(*[_w(ip, p) for ip, p in due])

    try:
        asyncio.run(_run())
    except Exception as e:
        log.exception("rescan: %s", e)
    finish_round(rid, len(due))
    return len(due)


def daemon(interval: int, ports: List[int], once: bool = False) -> None:
    """Continuous scanning: sweep every allowlisted range, sleep, repeat.

    `interval` is in seconds (the CLI takes hours and converts). Each sweep
    of each range opens its own scan round, which is what the timeline and
    the change feed are built on, so successive sweeps are directly
    comparable. The allowlist is re-read every cycle: adding a range takes
    effect at the next sweep without a restart.
    """
    interval = max(60, int(interval))
    stop = threading.Event()

    def _bye(signum, _frame):
        log.info("signal %s — finishing the current step, then stopping", signum)
        stop.set()

    for _sig in ("SIGINT", "SIGTERM", "SIGBREAK"):
        s = getattr(signal, _sig, None)
        if s is not None:
            try:
                signal.signal(s, _bye)
            except (ValueError, OSError):
                pass        # not the main thread, or unsupported on this OS

    # Liveness is written from its own thread so the dashboard can tell a
    # busy daemon from a dead one even during a long sweep.
    def _beat():
        while not stop.wait(DAEMON_HEARTBEAT):
            _daemon_set()
    threading.Thread(target=_beat, name="daemon-heartbeat", daemon=True).start()

    _daemon_set(status="starting", pid=os.getpid(), interval_seconds=interval,
                started_at=_utc(), cycles=0, cycle_started_at=None,
                last_cycle_at=None, next_scan_at=None, current_target="",
                ports=",".join(map(str, ports)), last_found=0, total_found=0,
                last_error="")
    log.info("Daemon up — interval %s (%.1f h), ports %d%s",
             interval, interval / 3600.0, len(ports), ", single cycle" if once else "")

    cycles = 0
    grand_total = 0
    try:
        while not stop.is_set():
            nets = load_allowlist()
            if not nets:
                log.error("No authorised ranges in %s — nothing to scan. "
                          "Add a CIDR and it is picked up within %ss.",
                          ALLOWLIST_FILE, ALLOWLIST_RETRY)
                _daemon_set(status="waiting", current_target="",
                            last_error=f"no CIDR ranges in {ALLOWLIST_FILE}",
                            next_scan_at=(datetime.now(timezone.utc) +
                                          timedelta(seconds=ALLOWLIST_RETRY)).isoformat())
                if once or stop.wait(ALLOWLIST_RETRY):
                    break
                continue

            _daemon_set(status="scanning", cycle_started_at=_utc(),
                        targets=",".join(str(n) for n in nets),
                        current_target="", last_error="")
            found = 0
            for net in nets:
                if stop.is_set():
                    break
                _daemon_set(current_target=str(net))
                try:
                    rid = asyncio.run(scan_cycle(str(net), ports, nets))
                    found += _round_total(rid)
                except Exception as e:
                    log.exception("scan %s: %s", net, e)
                    _daemon_set(last_error=f"{net}: {e}"[:400])

            if not stop.is_set():
                try:
                    found += rescan_due(ports, nets)
                except Exception as e:
                    log.exception("rescan: %s", e)
                    _daemon_set(last_error=f"rescan: {e}"[:400])

            cycles += 1
            grand_total += found
            if once or stop.is_set():
                _daemon_set(status="sleeping", cycles=cycles, last_cycle_at=_utc(),
                            current_target="", last_found=found,
                            total_found=grand_total)
                break

            nxt = datetime.now(timezone.utc) + timedelta(seconds=interval)
            _daemon_set(status="sleeping", cycles=cycles, last_cycle_at=_utc(),
                        current_target="", last_found=found,
                        total_found=grand_total, next_scan_at=nxt.isoformat())
            log.info("Cycle %d done — %d services. Next sweep %s (%.1f h)",
                     cycles, found, nxt.isoformat(timespec="seconds"),
                     interval / 3600.0)
            if stop.wait(interval):
                break
    finally:
        stop.set()
        _daemon_set(status="stopped", current_target="", next_scan_at=None)
        log.info("Daemon stopped after %d cycle(s), %d services", cycles, grand_total)


def _round_total(rid: int) -> int:
    try:
        conn = db()
        row = conn.execute(
            "SELECT total_found FROM scan_rounds WHERE round_id = ?", (rid,)).fetchone()
        conn.close()
        return int(row[0] or 0) if row else 0
    except sqlite3.Error:
        return 0

# ============================================================================
# HTTP API
# ============================================================================
def cmd_serve(args):
    init_db()
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlparse, parse_qs, unquote

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _send(self, obj, status=200):
            body = json.dumps(obj, default=str).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urlparse(self.path)
            qs = parse_qs(u.query)
            try:
                if u.path == "/search":
                    q = qs.get("q", ["*"])[0]
                    limit = int(qs.get("limit", ["50"])[0])
                    mode = qs.get("mode", ["keyword"])[0]
                    rows = run_fts(q, limit) if mode == "fts" else run_query(q, limit)
                    facets = qs.get("facets", [""])[0]
                    out = {"query": q, "count": len(rows), "results": rows}
                    if facets:
                        out["facets"] = {
                            f: run_facets(q, f, int(qs.get("facets_limit", ["20"])[0]))
                            for f in facets.split(",") if f.strip()
                        }
                    return self._send(out)
                if u.path == "/host/":
                    return self._send({"error": "use /host/<ip>[/<port>]"}, 400)
                if u.path.startswith("/host/"):
                    parts = [unquote(p) for p in u.path.split("/")[2:] if p]
                    if len(parts) == 1:
                        ip = parts[0]
                        mask = 128 if ":" in ip else 32
                        rows = run_query(f"ip:{ip}/{mask}", 1000)
                    else:
                        rows = run_query(f"ip:{parts[0]}/{128 if ':' in parts[0] else 32} "
                                         f"port:{parts[1]}", 10)
                    return self._send(rows)
                if u.path.startswith("/history/"):
                    parts = [unquote(p) for p in u.path.split("/")[2:] if p]
                    if len(parts) != 2:
                        return self._send({"error": "use /history/<ip>/<port>"}, 400)
                    conn = db(); conn.row_factory = sqlite3.Row
                    rows = [dict(r) for r in conn.execute(
                        "SELECT scan_round, seen_at, record_json FROM observations "
                        "WHERE ip=? AND port=? ORDER BY seen_at DESC LIMIT 200",
                        (parts[0], int(parts[1]))).fetchall()]
                    conn.close()
                    return self._send(rows)
                if u.path == "/stats":
                    conn = db()
                    stats = {}
                    for t in ("hosts","observations","scan_rounds","cve","kev","epss"):
                        try:
                            stats[t] = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                        except sqlite3.OperationalError: stats[t] = None
                    conn.close()
                    return self._send(stats)
                if u.path in ("/", ""):
                    return self._send({
                        "name": "CyberScan API",
                        "endpoints": [
                            "/search?q=<expr>&limit=N&mode=fts|keyword&facets=port,country&facets_limit=20",
                            "/host/<ip>[/<port>]",
                            "/history/<ip>/<port>",
                            "/stats",
                        ]})
                self._send({"error": "not found"}, 404)
            except Exception as e:
                self._send({"error": str(e)}, 500)

    server = ThreadingHTTPServer(("0.0.0.0", args.port), H)
    log.info("API listening on :%d", args.port)
    try: server.serve_forever()
    except KeyboardInterrupt: pass

# ============================================================================
# SHARD
# ============================================================================
def cmd_shard(args):
    net = ipaddress.ip_network(args.cidr)
    n = max(1, args.workers)
    bits = int(math.ceil(math.log2(n)))
    for s in net.subnets(prefixlen_diff=bits):
        print(s)

# ============================================================================
# CLI
# ============================================================================
def cmd_init(_):
    init_db()
    if not os.path.exists(ALLOWLIST_FILE):
        Path(ALLOWLIST_FILE).write_text(
            "# Authorized CIDR ranges only, one per line.\n"
            "# Example (RFC 5737 TEST-NET):\n# 192.0.2.0/28\n")

def cmd_sync_feeds(args):
    init_db()
    years = args.years or [2023, 2024, 2025, 2026]
    log.info("=== NVD ===")
    sync_nvd(years, args.force)
    log.info("=== CISA KEV ===")
    sync_kev()
    log.info("=== EPSS ===")
    sync_epss()

def cmd_scan(args):
    global GEO, CVE
    init_db()
    nets = load_allowlist()
    if not nets:
        log.error("Populate %s", ALLOWLIST_FILE); return
    cidr = args.cidr
    if not any(ipaddress.ip_network(cidr, strict=False).subnet_of(n)
               for n in nets if n.version == ipaddress.ip_network(cidr).version):
        log.error("%s not in allowlist", cidr); return
    GEO = GeoDB(); CVE = CveDB()
    load_public_suffixes()          # prime the list before any DNS work
    ports = [int(x) for x in args.ports.split(",")] if args.ports else TOP_PORTS
    for _ in range(args.rounds):
        asyncio.run(scan_cycle(cidr, ports, nets))
        if args.rounds > 1: time.sleep(args.sleep)

def cmd_daemon(args):
    global GEO, CVE
    init_db(); GEO = GeoDB(); CVE = CveDB()
    load_public_suffixes()          # prime the list before any DNS work
    ports = [int(x) for x in args.ports.split(",")] if args.ports else TOP_PORTS
    # --interval is in HOURS (the documented unit); --interval-seconds wins
    # when given, for cadences shorter than an hour.
    seconds = args.interval_seconds if args.interval_seconds \
        else int(round(float(args.interval) * 3600))
    daemon(seconds, ports, once=args.once)

def cmd_query(args):
    init_db()
    rows = run_fts(args.expression, args.limit) if args.fts \
           else run_query(args.expression, args.limit)
    print_rows(rows)
    if args.facets:
        facets = {f: run_facets(args.expression, f.strip(), args.facets_limit)
                  for f in args.facets.split(",") if f.strip()}
        print_facets(facets)

def cmd_diff(args):
    init_db(); diff_rounds(args.round_a, args.round_b)

def cmd_history(args):
    init_db()
    conn = db(); conn.row_factory = sqlite3.Row
    q = "SELECT scan_round, seen_at, record_json FROM observations WHERE 1=1"
    p = []
    if args.ip: q += " AND ip = ?"; p.append(args.ip)
    if args.port: q += " AND port = ?"; p.append(args.port)
    q += " ORDER BY seen_at DESC LIMIT 200"
    for r in conn.execute(q, p).fetchall():
        rec = json.loads(r["record_json"])
        print(f"[r{r['scan_round']:>4}] {r['seen_at']} "
              f"{rec.get('product','')} {rec.get('version','')} "
              f"KEV={','.join(rec.get('kev') or []) or '-'} "
              f"CVEs={','.join(rec.get('cves') or [])[:40] or '-'}")
    conn.close()

def cmd_import_csv(args):
    global GEO
    os.environ["ASN_CSV"] = args.path
    GEO = GeoDB()
    log.info("Loaded %d ranges — set ASN_CSV=%s", len(GEO._r), args.path)

def cmd_stats(_):
    init_db(); conn = db()
    for t in ("hosts","observations","scan_rounds","cve","kev","epss"):
        try:
            n = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            print(f"{t:<15} {n:>12,}")
        except sqlite3.OperationalError:
            print(f"{t:<15} {'(missing)':>12}")
    print("\nTop products:")
    for r in conn.execute(
        "SELECT product, COUNT(*) c FROM hosts WHERE product != '' "
        "GROUP BY product ORDER BY c DESC LIMIT 15"):
        print(f"  {r[0]:<30} {r[1]:>6}")
    print("\nTop ports:")
    for r in conn.execute(
        "SELECT port, COUNT(*) c FROM hosts GROUP BY port ORDER BY c DESC LIMIT 15"):
        print(f"  {r[0]:<6} {r[1]:>6}")
    print("\nKEV hits:")
    for r in conn.execute(
        "SELECT ip, port, cves FROM hosts WHERE kev != '' LIMIT 10"):
        print(f"  {r[0]}:{r[1]}  {r[2]}")
    conn.close()

def main():
    ap = argparse.ArgumentParser(description="CyberScan v3 — single-file cyberspace search engine")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init").set_defaults(fn=cmd_init)

    p = sub.add_parser("sync-feeds", help="sync NVD + KEV + EPSS")
    p.add_argument("--years", type=int, nargs="+")
    p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_sync_feeds)

    p = sub.add_parser("scan")
    p.add_argument("--cidr", required=True)
    p.add_argument("--ports")
    p.add_argument("--rounds", type=int, default=1)
    p.add_argument("--sleep", type=int, default=60)
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("daemon", help="continuously re-scan every allowlisted range")
    p.add_argument("--interval", type=float, default=24,
                   metavar="HOURS", help="hours between sweeps (default 24)")
    p.add_argument("--interval-seconds", type=int, default=0,
                   metavar="N", help="override --interval with an exact second count")
    p.add_argument("--ports", help="comma-separated ports (default: top 56)")
    p.add_argument("--once", action="store_true",
                   help="run a single sweep and exit, for cron or systemd timers")
    p.set_defaults(fn=cmd_daemon)

    p = sub.add_parser("query")
    p.add_argument("expression")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--facets", help="comma list: port,country,product,asn,...")
    p.add_argument("--facets-limit", type=int, default=20)
    p.add_argument("--fts", action="store_true", help="use FTS5 full-text")
    p.set_defaults(fn=cmd_query)

    p = sub.add_parser("diff")
    p.add_argument("--round-a", type=int, required=True)
    p.add_argument("--round-b", type=int, required=True)
    p.set_defaults(fn=cmd_diff)

    p = sub.add_parser("history")
    p.add_argument("--ip"); p.add_argument("--port", type=int)
    p.set_defaults(fn=cmd_history)

    p = sub.add_parser("serve")
    p.add_argument("--port", type=int, default=8080)
    p.set_defaults(fn=cmd_serve)

    p = sub.add_parser("shard")
    p.add_argument("--cidr", required=True)
    p.add_argument("--workers", type=int, default=4)
    p.set_defaults(fn=cmd_shard)

    p = sub.add_parser("import-csv")
    p.add_argument("path"); p.set_defaults(fn=cmd_import_csv)

    sub.add_parser("stats").set_defaults(fn=cmd_stats)

    args = ap.parse_args()
    args.fn(args)

if __name__ == "__main__":
    main()
# ============================================================================
# NORTHHARV INTELLIGENCE LAYER
# Schema migrations, risk scoring, fingerprinting, enrichment, change feed.
# ============================================================================
import base64  # the rest of the stdlib is already imported above
from engine import signatures as SIG

# ── Schema migrations ───────────────────────────────────────────────────────
# column name -> DDL type/default. Applied additively; existing data is kept.
# ── Auto-tag detection ──────────────────────────────────────────────────────
_CAMERA_PORTS = frozenset({554, 8554, 10554, 8181, 34567, 37777})

_CAMERA_KEYWORDS = frozenset({
    "hikvision", "dahua", "axis communications", "vivotek", "foscam",
    "amcrest", "reolink", "ubiquiti", "hanwha", "bosch security", "pelco",
    "uniview", "milesight", "tiandy", "geovision", "mobotix", "avigilon",
    "flir", "arecont", "vstarcam", "lorex", "annke", "zosi",
    "ip camera", "ipcamera", "net camera", "netcam", "webcam", "webeye",
    "netwave ip", "nvr", "dvr", "cctv", "video surveillance",
    "surveillance camera", "security camera", "onvif", "rtsp/",
    "stream.mjpeg", "/videostream", "/video.cgi", "/snapshot.cgi",
    "mjpeg", "mjpg-streamer",
})

_LOGIN_TITLE_WORDS = frozenset({
    "login", "log in", "sign in", "signin", "logon", "log-in",
    "authentication", "authenticate", "user login", "admin login",
    "please login", "please log in", "please sign in",
})

_ADMIN_KEYWORDS = frozenset({
    "phpmyadmin", "webmin", "cpanel", "plesk", "directadmin",
    "admin panel", "admin console", "control panel", "management console",
    "web manager", "router admin", "router login", "modem login",
    "switch admin", "firewall admin", "dashboard — admin",
    "admin — dashboard", "admin dashboard", "management interface",
    "device manager", "system management",
})

_DEFAULT_CRED_KEYWORDS = frozenset({
    "default password", "default credentials", "factory password",
    "admin/admin", "admin:admin", "default username", "password: admin",
})

_EXPOSED_DB_SERVICES = frozenset({
    "redis", "memcached", "mongodb", "elasticsearch", "cassandra",
    "couchdb", "influxdb", "clickhouse",
    # relational / common DBs that also appear unauthenticated on public internet
    "mysql", "postgresql", "mssql", "ms-sql-s", "mariadb", "neo4j",
    "oracle", "db2",
})


def compute_auto_tags(port: int, service_name: str, product: str,
                      banner: str, http_title: str, http_headers: str) -> str:
    """Detect camera, RTSP, ONVIF, login panels, admin interfaces, exposed DBs.

    Returns comma-separated sorted tag string stored in hosts.tags.
    """
    tags: set[str] = set()
    sn    = (service_name or "").lower()
    prod  = (product or "").lower()
    ban   = (banner or "")[:2000].lower()
    title = (http_title or "").lower()
    hdrs  = (http_headers or "")[:1000].lower()
    full  = f"{prod} {ban} {title} {hdrs}"

    # ── RTSP / camera ──────────────────────────────────────────────────────
    if port in _CAMERA_PORTS or sn == "rtsp" or "rtsp/" in ban:
        tags.add("rtsp")
    if "onvif" in full:
        tags.add("onvif")
    if any(kw in full for kw in _CAMERA_KEYWORDS):
        tags.add("camera")
    if "rtsp" in tags or "onvif" in tags:
        tags.add("camera")

    # ── Open directory listing ─────────────────────────────────────────────
    if "index of /" in title or "directory listing" in title or "parent directory" in ban:
        tags.add("open_dir")

    # ── Login panel ────────────────────────────────────────────────────────
    if any(w in title for w in _LOGIN_TITLE_WORDS):
        tags.add("login_panel")

    # ── Admin / management panel ───────────────────────────────────────────
    if any(kw in full for kw in _ADMIN_KEYWORDS):
        tags.add("admin_panel")

    # ── Default credentials page ───────────────────────────────────────────
    if any(kw in full for kw in _DEFAULT_CRED_KEYWORDS):
        tags.add("default_creds")

    # ── Exposed database / infra with no auth ─────────────────────────────
    if sn in _EXPOSED_DB_SERVICES:
        tags.add("exposed_db")
    if sn == "docker":
        tags.add("exposed_docker")
    if sn in ("kubernetes-api", "kubernetes"):
        tags.add("exposed_k8s")

    return ",".join(sorted(tags))


def backfill_tags() -> dict:
    """Re-compute and persist tags for every host that currently has tags=''.

    Safe to call at startup; uses a single transaction per 500-row batch.
    Returns diagnostic counts.
    """
    conn = db()
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT ip, port, service_name, product, banner, http_title, http_headers "
        "FROM hosts WHERE tags = '' OR tags IS NULL"
    ).fetchall()
    total = len(rows)
    updated = 0
    per_tag: dict[str, int] = {}
    try:
        batch: list[tuple] = []
        for r in rows:
            new_tags = compute_auto_tags(
                r["port"],
                r["service_name"] or "",
                r["product"] or "",
                r["banner"] or "",
                r["http_title"] or "",
                r["http_headers"] or "",
            )
            if not new_tags:
                continue
            batch.append((new_tags, r["ip"], r["port"]))
            for t in new_tags.split(","):
                per_tag[t] = per_tag.get(t, 0) + 1
            if len(batch) >= 500:
                conn.executemany(
                    "UPDATE hosts SET tags=? WHERE ip=? AND port=?", batch)
                updated += len(batch)
                batch = []
        if batch:
            conn.executemany(
                "UPDATE hosts SET tags=? WHERE ip=? AND port=?", batch)
            updated += len(batch)
        # Rebuild host_tags for all rows that now have tags
        if updated:
            for row in conn.execute(
                    "SELECT tags, ip, port FROM hosts WHERE tags != '' AND tags IS NOT NULL"
            ).fetchall():
                row_tags = row[0]; ip = row[1]; port = row[2]
                conn.execute(
                    "DELETE FROM host_tags WHERE ip=? AND port=?", (ip, port))
                for tag in row_tags.split(","):
                    if tag:
                        conn.execute(
                            "INSERT OR IGNORE INTO host_tags (ip, port, tag) VALUES (?,?,?)",
                            (ip, port, tag))
        conn.commit()
    except Exception as exc:
        log.warning("backfill_tags: %s", exc)
    finally:
        conn.close()
    log.info(
        "backfill_tags: inspected=%d updated=%d per_tag=%s",
        total, updated, per_tag)
    return {"inspected": total, "updated": updated, "per_tag": per_tag}


HOST_MIGRATIONS = {
    "risk_score":     "INTEGER DEFAULT 0",
    "techs":          "TEXT DEFAULT ''",
    "hostname":       "TEXT DEFAULT ''",
    "domain":         "TEXT DEFAULT ''",
    "tags":           "TEXT DEFAULT ''",
    "icon_hash":      "INTEGER DEFAULT 0",
    "jarm":           "TEXT DEFAULT ''",
    "hassh":          "TEXT DEFAULT ''",
    "ja3s":           "TEXT DEFAULT ''",
    "http_status":    "INTEGER DEFAULT 0",
    "http_headers":   "TEXT DEFAULT ''",
    "waf":            "TEXT DEFAULT ''",
    "cloud_provider": "TEXT DEFAULT ''",
}

EXTRA_SCHEMA = """
CREATE TABLE IF NOT EXISTS hostnames (
    ip TEXT NOT NULL,
    hostname TEXT NOT NULL,
    source TEXT DEFAULT 'rdns',
    resolved_at TEXT,
    PRIMARY KEY (ip, hostname)
);
CREATE TABLE IF NOT EXISTS watchlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern TEXT NOT NULL,
    label TEXT DEFAULT '',
    type TEXT DEFAULT 'query',
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS host_tags (
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    tag TEXT NOT NULL,
    PRIMARY KEY (ip, port, tag)
);
-- One row, id 1: what the continuous-scanning daemon is doing right now.
-- The web UI reads it; the daemon is the only writer.
CREATE TABLE IF NOT EXISTS daemon_state (
    id               INTEGER PRIMARY KEY CHECK (id = 1),
    status           TEXT    DEFAULT 'stopped',
    pid              INTEGER DEFAULT 0,
    interval_seconds INTEGER DEFAULT 86400,
    started_at       TEXT,
    heartbeat_at     TEXT,
    cycle_started_at TEXT,
    last_cycle_at    TEXT,
    next_scan_at     TEXT,
    cycles           INTEGER DEFAULT 0,
    current_target   TEXT    DEFAULT '',
    targets          TEXT    DEFAULT '',
    ports            TEXT    DEFAULT '',
    last_found       INTEGER DEFAULT 0,
    total_found      INTEGER DEFAULT 0,
    last_error       TEXT    DEFAULT ''
);
-- Internet crawl state: one singleton row (id=1). LCG cursor enables O(1) resume.
CREATE TABLE IF NOT EXISTS crawl_state (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    started_at   TEXT,
    last_chunk   TEXT    DEFAULT '',
    chunks_done  INTEGER DEFAULT 0,
    chunks_total INTEGER DEFAULT 0,
    status       TEXT    DEFAULT 'stopped',
    scan_name    TEXT    DEFAULT '',
    ports        TEXT    DEFAULT '',
    lcg_state    INTEGER DEFAULT 0,
    lcg_start    INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_hosts_risk   ON hosts(risk_score);
CREATE INDEX IF NOT EXISTS idx_hosts_ip     ON hosts(ip);
CREATE INDEX IF NOT EXISTS idx_hosts_domain ON hosts(domain);
CREATE INDEX IF NOT EXISTS idx_hostnames_nm ON hostnames(hostname);
-- PCI/payment-card findings: masked PANs only, never plaintext card numbers.
CREATE TABLE IF NOT EXISTS pci_findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           TEXT    NOT NULL,
    port         INTEGER NOT NULL,
    service_name TEXT    DEFAULT '',
    detected_at  TEXT    NOT NULL,
    card_network TEXT    DEFAULT '',
    luhn_valid   INTEGER DEFAULT 0,
    masked_pan   TEXT    NOT NULL,
    bin_prefix   TEXT    DEFAULT '',
    issuer       TEXT    DEFAULT '',
    country      TEXT    DEFAULT '',
    funding_type TEXT    DEFAULT '',
    UNIQUE (ip, port, masked_pan)
);
CREATE INDEX IF NOT EXISTS idx_pci_ip      ON pci_findings(ip);
CREATE INDEX IF NOT EXISTS idx_pci_net     ON pci_findings(card_network);
CREATE INDEX IF NOT EXISTS idx_pci_ts      ON pci_findings(detected_at);
"""


def _table_columns(conn, table: str) -> set:
    """Existing column names — always consulted before any ALTER TABLE."""
    try:
        return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    except sqlite3.OperationalError:
        return set()


def migrate_schema(conn=None) -> List[str]:
    """Add any missing columns/tables. Returns the list of applied changes."""
    own = conn is None
    if own:
        conn = db()
    applied = []
    try:
        cols = _table_columns(conn, "hosts")
        if cols:                      # only migrate a table that exists
            for name, ddl in HOST_MIGRATIONS.items():
                if name not in cols:
                    try:
                        conn.execute(f"ALTER TABLE hosts ADD COLUMN {name} {ddl}")
                        applied.append(f"hosts.{name}")
                    except sqlite3.OperationalError as e:
                        log.warning("migration hosts.%s failed: %s", name, e)
        conn.executescript(EXTRA_SCHEMA)
        conn.commit()
    finally:
        if own:
            conn.close()
    if applied:
        log.info("schema migrated: %s", ", ".join(applied))
    return applied


# ── MurmurHash3 (x86, 32-bit) ───────────────────────────────────────────────
def murmur3_32(data: bytes, seed: int = 0) -> int:
    """
    MurmurHash3 x86 32-bit, returned as a SIGNED integer.

    Matches mmh3.hash(), which is what Shodan and FOFA use for favicon hashes.
    """
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded = (length & ~0x3)

    for i in range(0, rounded, 4):
        k1 = struct.unpack_from("<I", data, i)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    # tail
    k1 = 0
    tail = length & 0x3
    if tail >= 3:
        k1 ^= data[rounded + 2] << 16
    if tail >= 2:
        k1 ^= data[rounded + 1] << 8
    if tail >= 1:
        k1 ^= data[rounded]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    # finalisation
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hash_from_bytes(raw: bytes) -> int:
    """
    FOFA/Shodan icon_hash: base64 the icon with a line break every 76 chars
    (exactly what `codecs.encode(raw, "base64")` produces, trailing newline
    included), then MurmurHash3-32 that text.
    """
    b64 = base64.encodebytes(raw)          # 76-char lines + trailing \n
    return murmur3_32(b64)


def fetch_icon_hash(url: str, timeout: int = 10) -> int:
    """
    Fetch a favicon and return its FOFA-compatible icon_hash.

    `url` may be a site root or a direct favicon URL; a bare host gets
    /favicon.ico appended. Returns 0 when the icon cannot be retrieved.
    """
    if not url:
        return 0
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if not url.rstrip("/").lower().endswith((".ico", ".png", ".gif", ".jpg", ".svg")):
        url = url.rstrip("/") + "/favicon.ico"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NorthHarv/1.0"})
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            raw = r.read(1 << 20)
    except Exception as e:
        log.debug("favicon %s: %s", url, e)
        return 0
    return favicon_hash_from_bytes(raw) if raw else 0


# ── Reverse DNS ─────────────────────────────────────────────────────────────
def reverse_dns(ip: str, timeout: float = 3.0) -> str:
    """PTR lookup for an IP. Returns '' when there is no record."""
    if not ip:
        return ""
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        host, aliases, _addrs = socket.gethostbyaddr(ip)
        name = (host or "").strip(".").lower()
        if name:
            _store_hostname(ip, name, "rdns")
            for a in aliases or []:
                a = (a or "").strip(".").lower()
                if a and a != name:
                    _store_hostname(ip, a, "rdns-alias")
        return name
    except (socket.herror, socket.gaierror, OSError):
        return ""
    finally:
        socket.setdefaulttimeout(old)


def _store_hostname(ip: str, hostname: str, source: str = "rdns") -> None:
    try:
        conn = db()
        conn.execute(
            "INSERT OR REPLACE INTO hostnames (ip, hostname, source, resolved_at)"
            " VALUES (?,?,?,?)",
            (ip, hostname, source, datetime.now(timezone.utc).isoformat()))
        conn.commit()
        conn.close()
    except sqlite3.Error:
        pass


def hostnames_for(ip: str) -> List[str]:
    try:
        conn = db()
        rows = conn.execute(
            "SELECT hostname FROM hostnames WHERE ip=? ORDER BY hostname", (ip,)).fetchall()
        conn.close()
        return [r[0] for r in rows]
    except sqlite3.Error:
        return []


# ============================================================================
# DNS RESOLUTION — reverse, registrable domain, forward
# ============================================================================
# Reverse DNS gives a name; the name gives a domain; the domain's A records
# give addresses the port sweep may never have reached. The allowlist is
# applied to every address that comes back, so this can only ever deepen the
# picture of an authorised range, never reach outside one.

PUBLIC_SUFFIX_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
PSL_CACHE         = Path(__file__).parent / "cache" / "public_suffix_list.dat"
PSL_MAX_AGE       = 30 * 86400

# Enough of the list to be correct offline. Single-label suffixes need no
# entry — the PSL's default rule already treats any unknown TLD as one
# label — so only the multi-label suffixes have to be spelled out here.
_PSL_FALLBACK = {
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "net.uk", "sch.uk",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ad.jp", "ed.jp", "lg.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz",
    "co.za", "org.za", "net.za", "gov.za", "ac.za", "web.za",
    "com.mx", "org.mx", "net.mx", "gob.mx", "edu.mx",
    "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar",
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
    "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk", "idv.hk",
    "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw", "idv.tw",
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "k12.tr",
    "com.ua", "net.ua", "org.ua", "gov.ua", "edu.ua", "in.ua",
    "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl", "waw.pl",
    "com.ru", "net.ru", "org.ru", "gov.ru", "edu.ru", "msk.ru", "spb.ru",
    "co.kr", "ne.kr", "or.kr", "go.kr", "re.kr", "pe.kr",
    "co.id", "net.id", "or.id", "go.id", "ac.id", "web.id", "my.id",
    "co.th", "net.th", "or.th", "go.th", "ac.th", "in.th",
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn",
    "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk",
    "com.eg", "net.eg", "org.eg", "gov.eg", "edu.eg",
    "com.ng", "net.ng", "org.ng", "gov.ng", "edu.ng",
    "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa",
    "co.il", "net.il", "org.il", "gov.il", "ac.il", "muni.il",
    "com.es", "org.es", "nom.es", "gob.es", "edu.es",
    "com.pt", "org.pt", "gov.pt", "edu.pt", "nome.pt",
    "com.gr", "net.gr", "org.gr", "gov.gr", "edu.gr",
    "com.co", "net.co", "nom.co", "gov.co", "edu.co",
    "com.pe", "net.pe", "org.pe", "gob.pe", "edu.pe",
    "com.cy", "com.ec", "com.uy", "com.ve", "com.do", "com.gt", "com.bo",
    "com.cu", "com.ni", "com.pa", "com.py", "com.sv", "com.hn",
    "co.ke", "co.tz", "co.ug", "co.zw", "co.mz", "co.ao",
    # multi-label suffixes under generic TLDs that behave the same way
    "s3.amazonaws.com", "cloudfront.net", "elb.amazonaws.com",
    "compute.amazonaws.com", "compute-1.amazonaws.com",
    "azurewebsites.net", "cloudapp.azure.com", "cloudapp.net",
    "appspot.com", "run.app", "web.app", "firebaseapp.com",
    "github.io", "gitlab.io", "pages.dev", "workers.dev", "netlify.app",
    "vercel.app", "herokuapp.com", "digitaloceanspaces.com",
}

_PSL: Optional[set] = None
_PSL_LOCK = threading.Lock()


def _psl_parse(text: str) -> set:
    """Rules only: comments, blank lines and the ICANN/PRIVATE markers go."""
    rules = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        rules.add(line.lower())
    return rules


def load_public_suffixes(refresh: bool = False) -> set:
    """The public suffix list, from cache, else downloaded, else built in."""
    global _PSL
    with _PSL_LOCK:
        if _PSL is not None and not refresh:
            return _PSL

        fresh = False
        if PSL_CACHE.exists() and not refresh:
            fresh = (time.time() - PSL_CACHE.stat().st_mtime) < PSL_MAX_AGE
        if not fresh:
            try:
                PSL_CACHE.parent.mkdir(parents=True, exist_ok=True)
                tmp = PSL_CACHE.parent / (PSL_CACHE.name + ".part")
                req = urllib.request.Request(
                    PUBLIC_SUFFIX_URL, headers={"User-Agent": "NorthHarv"})
                with urllib.request.urlopen(req, timeout=30) as r:
                    data = r.read()
                if len(data) > 20000:          # a truncated list is worse than none
                    tmp.write_bytes(data)
                    os.replace(tmp, PSL_CACHE)
                    log.info("public suffix list refreshed (%d KiB)", len(data) // 1024)
            except Exception as e:
                log.debug("public suffix list download failed: %s", e)

        rules = set()
        if PSL_CACHE.exists():
            try:
                rules = _psl_parse(PSL_CACHE.read_text(encoding="utf-8", errors="replace"))
            except OSError as e:
                log.debug("public suffix cache unreadable: %s", e)
        if len(rules) < 100:
            log.info("public suffix list unavailable — using the built-in subset")
            rules = set(_PSL_FALLBACK)
        _PSL = rules
        return _PSL


def _clean_host(name: str) -> str:
    name = (name or "").strip().strip(".").lower()
    if not name or len(name) > 253:
        return ""
    # a PTR record is attacker-controlled text; only real hostname characters
    # may reach the database or another resolver call
    if not re.fullmatch(r"[a-z0-9]([a-z0-9._-]*[a-z0-9])?", name):
        return ""
    return name


def root_domain(hostname: str) -> str:
    """The registrable domain of a hostname, by public-suffix rules.

    www.shop.example.co.uk -> example.co.uk      (multi-label suffix)
    host-12.corp.example.com -> example.com
    example.com            -> example.com
    co.uk                  -> ''                 (a suffix is not a domain)

    A name that is itself a public suffix has no registrable domain, so a
    provider-assigned reverse name such as
    ec2-52-1-2-3.compute-1.amazonaws.com returns '' — nobody registered it,
    and grouping hosts by it would put every host in its own group. Cloud
    attribution for those is the job of detect_cloud(), not of this.
    """
    name = _clean_host(hostname)
    if not name or _is_ip_literal(name):
        return ""
    labels = name.split(".")
    if len(labels) < 2 or any(not l for l in labels):
        return ""

    rules = load_public_suffixes()
    suffix_len = 0
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        # an exception rule (!) shortens the prevailing suffix by one label
        if "!" + candidate in rules:
            suffix_len = len(labels) - i - 1
            break
        if candidate in rules:
            suffix_len = max(suffix_len, len(labels) - i)
        if ".".join(["*"] + labels[i + 1:]) in rules:
            suffix_len = max(suffix_len, len(labels) - i)
    if suffix_len == 0:
        suffix_len = 1                 # the list's default rule: "*"
    if suffix_len >= len(labels):
        return ""                      # the whole name is a public suffix
    return ".".join(labels[-(suffix_len + 1):])


def _store_hostnames_bulk(rows: List[Tuple[str, str, str]]) -> None:
    """rows: (ip, hostname, source). One connection for the whole batch."""
    rows = [(ip, h, s) for ip, h, s in rows if ip and h]
    if not rows:
        return
    now = _utc()
    try:
        conn = db()
        conn.executemany(
            "INSERT OR REPLACE INTO hostnames (ip, hostname, source, resolved_at)"
            " VALUES (?,?,?,?)", [(ip, h, s, now) for ip, h, s in rows])
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        log.debug("hostname store failed: %s", e)


def resolve_host_dns(ip: str, timeout: float = 3.0) -> Dict[str, Any]:
    """Reverse-resolve an IP, then derive the registrable domain of each name.

    Every name and domain found is written to the hostnames table, tagged
    with how it was learned. Returns the primary name, its domain, and the
    full set, for the caller to store on the host row.
    """
    out: Dict[str, Any] = {"ip": ip, "hostname": "", "domain": "",
                           "hostnames": [], "domains": []}
    if not ip:
        return out

    old = socket.getdefaulttimeout()
    primary, aliases = "", []
    try:
        socket.setdefaulttimeout(timeout)
        host, alias_list, _addrs = socket.gethostbyaddr(ip)
        primary = _clean_host(host)
        aliases = [a for a in (_clean_host(x) for x in (alias_list or [])) if a]
    except (socket.herror, socket.gaierror, OSError):
        return out
    finally:
        socket.setdefaulttimeout(old)

    names, seen = [], set()
    for n in [primary] + aliases:
        if n and n not in seen:
            seen.add(n); names.append(n)
    if not names:
        return out

    rows = [(ip, n, "rdns" if n == primary else "rdns-alias") for n in names]
    domains = []
    for n in names:
        d = root_domain(n)
        if d and d not in domains:
            domains.append(d)
    rows += [(ip, d, "domain") for d in domains if d not in seen]
    _store_hostnames_bulk(rows)

    out["hostname"] = primary
    out["hostnames"] = names
    out["domains"] = domains
    out["domain"] = root_domain(primary) or (domains[0] if domains else "")
    return out


def forward_dns(name: str, timeout: float = 3.0) -> List[str]:
    """Every A record for a name, in the order the resolver returned them.

    IPv4 only: the allowlist, the port sweep and the host table are all
    IPv4, so an AAAA answer could not be scanned or stored anyway.
    """
    name = _clean_host(name)
    if not name or _is_ip_literal(name):
        return []
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return []
    finally:
        socket.setdefaulttimeout(old)

    ips, seen = [], set()
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.add(addr); ips.append(addr)
    return ips


DNS_EXPAND_MAX_NAMES = 256      # names forward-resolved per scan round
DNS_EXPAND_MAX_IPS   = 1024     # new addresses admitted per scan round


def dns_expand(names: List[str], nets, exclude: Optional[set] = None) -> List[str]:
    """Forward-resolve names and return the authorised addresses that are new.

    An address is admitted only when the allowlist already covers it, so a
    hostile or misconfigured DNS answer cannot steer the scanner at a
    network nobody authorised. Each admitted address is recorded against
    the name that produced it.
    """
    if not names or not nets:
        return []
    exclude = set(exclude or ())
    out, rows = [], []
    for name in names[:DNS_EXPAND_MAX_NAMES]:
        for ip in forward_dns(name):
            rows.append((ip, name, "a-record"))
            if ip in exclude:
                continue
            try:
                if not allowed(ip, nets):
                    log.debug("DNS expansion: %s -> %s outside the allowlist", name, ip)
                    continue
            except ValueError:
                continue
            exclude.add(ip)
            out.append(ip)
            if len(out) >= DNS_EXPAND_MAX_IPS:
                break
        if len(out) >= DNS_EXPAND_MAX_IPS:
            break
    # names resolving to an authorised address are worth keeping either way
    _store_hostnames_bulk([r for r in rows if r[0] in exclude])
    return out


# ── Cloud provider detection ────────────────────────────────────────────────
CLOUD_RANGE_URLS = {
    "AWS": "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "GCP": "https://www.gstatic.com/ipranges/cloud.json",
}
CLOUD_CACHE = Path(__file__).parent / "cache" / "cloud_ranges.json"
CLOUD_MAX_AGE = 7 * 86400

# provider -> list of (network_int_low, network_int_high)
_CLOUD_NETS: Dict[str, List[Tuple[int, int]]] = {}
_CLOUD_LOADED = False

CLOUD_ORG_HINTS = [
    ("AWS",          ("amazon", "aws", "ec2", "amazon technologies", "a100 row")),
    ("GCP",          ("google cloud", "gcp", "google llc", "google inc")),
    ("Azure",        ("microsoft", "azure", "msn")),
    ("DigitalOcean", ("digitalocean", "digital ocean")),
    ("Linode",       ("linode", "akamai connected cloud")),
    ("Vultr",        ("vultr", "choopa")),
    ("Hetzner",      ("hetzner",)),
    ("OVH",          ("ovh",)),
    ("Oracle Cloud", ("oracle",)),
    ("Alibaba Cloud", ("alibaba", "aliyun")),
    ("Cloudflare",   ("cloudflare",)),
]


def _cidr_bounds(cidr: str) -> Optional[Tuple[int, int]]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return int(net.network_address), int(net.broadcast_address)
    except ValueError:
        return None


def refresh_cloud_ranges(force: bool = False) -> Dict[str, int]:
    """
    Download and cache published cloud IP ranges.

    Azure is intentionally absent: its ServiceTags download URL embeds a
    rotating release id and has no stable raw endpoint, so Azure falls back
    to organisation-string matching.
    """
    global _CLOUD_LOADED
    fresh = None
    if not force and CLOUD_CACHE.exists():
        try:
            age = time.time() - CLOUD_CACHE.stat().st_mtime
            if age <= CLOUD_MAX_AGE:
                fresh = json.loads(CLOUD_CACHE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            fresh = None

    if fresh is None:
        collected: Dict[str, List[str]] = {}
        for provider, url in CLOUD_RANGE_URLS.items():
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "NorthHarv/1.0"})
                with urllib.request.urlopen(req, timeout=60) as r:
                    blob = json.loads(r.read())
            except Exception as e:
                log.warning("cloud ranges %s: %s", provider, e)
                continue
            cidrs: List[str] = []
            if provider == "AWS":
                for p in blob.get("prefixes", []):
                    if p.get("ip_prefix"):
                        cidrs.append(p["ip_prefix"])
                for p in blob.get("ipv6_prefixes", []):
                    if p.get("ipv6_prefix"):
                        cidrs.append(p["ipv6_prefix"])
            elif provider == "GCP":
                for p in blob.get("prefixes", []):
                    v = p.get("ipv4Prefix") or p.get("ipv6Prefix")
                    if v:
                        cidrs.append(v)
            if cidrs:
                collected[provider] = cidrs
        if collected:
            fresh = collected
            try:
                CLOUD_CACHE.parent.mkdir(parents=True, exist_ok=True)
                CLOUD_CACHE.write_text(json.dumps(fresh), encoding="utf-8")
            except OSError:
                pass
        elif CLOUD_CACHE.exists():
            try:
                fresh = json.loads(CLOUD_CACHE.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                fresh = {}

    _CLOUD_NETS.clear()
    for provider, cidrs in (fresh or {}).items():
        bounds = [b for b in (_cidr_bounds(c) for c in cidrs) if b]
        bounds.sort()
        _CLOUD_NETS[provider] = bounds
    _CLOUD_LOADED = True
    return {k: len(v) for k, v in _CLOUD_NETS.items()}


def _cloud_by_range(ip: str) -> str:
    if not _CLOUD_LOADED:
        return ""
    try:
        n = int(ipaddress.ip_address(ip))
    except ValueError:
        return ""
    for provider, bounds in _CLOUD_NETS.items():
        lo = bisect.bisect_right(bounds, (n, float("inf"))) - 1
        if lo >= 0 and bounds[lo][0] <= n <= bounds[lo][1]:
            return provider
    return ""


def detect_cloud(ip: str = "", org: str = "", banner: str = "") -> str:
    """Which cloud an address belongs to: published ranges first, then org."""
    hit = _cloud_by_range(ip)
    if hit:
        return hit
    hay = f"{org} {banner}".lower()
    for provider, hints in CLOUD_ORG_HINTS:
        if any(h in hay for h in hints):
            return provider
    return ""


# ── WAF detection ───────────────────────────────────────────────────────────
def detect_waf(headers_str: str = "", body: str = "") -> str:
    """Match identYwaf signatures against the response headers and body."""
    hay = f"{headers_str}\n{body}"
    if not hay.strip():
        return ""
    for name, pattern in SIG.WAF_SIGNATURES.items():
        rx = SIG.compiled("waf", pattern)
        if rx is not None and rx.search(hay):
            return name
    return ""


# ── Technology fingerprinting ───────────────────────────────────────────────
def _extract_version(spec: Optional[str], match: "re.Match") -> str:
    r"""
    Resolve a Wappalyzer version spec against a regex match.

    Handles the plain back-reference form (\1) and the ternary form
    (\1?a:b) that picks one of two literals depending on whether the group
    matched.
    """
    if not spec:
        return ""
    out = spec
    tern = re.match(r"^\\(\d+)\?([^:]*):(.*)$", spec)
    if tern:
        idx = int(tern.group(1))
        try:
            got = match.group(idx)
        except IndexError:
            got = None
        return tern.group(2) if got else tern.group(3)
    for m in re.finditer(r"\\(\d+)", spec):
        idx = int(m.group(1))
        try:
            val = match.group(idx) or ""
        except IndexError:
            val = ""
        out = out.replace(m.group(0), val)
    return out.strip()


def detect_technologies(banner: str = "", body: str = "",
                        headers: Any = "", url: str = "") -> List[Dict[str, Any]]:
    """
    Identify technologies from a response, Wappalyzer-style.

    Returns [{name, version, confidence, category}], de-duplicated with the
    highest-confidence hit winning, and implied technologies folded in.
    """
    if isinstance(headers, dict):
        headers_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
    else:
        headers_str = str(headers or "")

    body_hay = f"{banner or ''}\n{body or ''}"
    targets = {"body": body_hay, "headers": headers_str, "url": url or ""}
    if not any(v.strip() for v in targets.values()):
        return []

    found: Dict[str, Dict[str, Any]] = {}

    for name, sig in SIG.TECH_SIGNATURES.items():
        best: Optional[Dict[str, Any]] = None
        for target, patterns in sig.get("patterns", {}).items():
            hay = targets.get(target, "")
            if not hay:
                continue
            for regex, ver_spec, conf in patterns:
                rx = SIG.compiled("tech", regex)
                if rx is None:
                    continue
                m = rx.search(hay)
                if not m:
                    continue
                version = _extract_version(ver_spec, m)
                if best is None or conf > best["confidence"] or (version and not best["version"]):
                    cats = sig.get("cats") or []
                    best = {
                        "name": name,
                        "version": version,
                        "confidence": conf,
                        "category": SIG.CATEGORIES.get(str(cats[0]), "") if cats else "",
                    }
        if best:
            found[name] = best

    # fold in implied technologies (WordPress -> PHP, MySQL)
    for name in list(found):
        for implied in SIG.TECH_SIGNATURES.get(name, {}).get("implies", []):
            if implied and implied not in found:
                cats = SIG.TECH_SIGNATURES.get(implied, {}).get("cats") or []
                found[implied] = {
                    "name": implied, "version": "", "confidence": 50,
                    "category": SIG.CATEGORIES.get(str(cats[0]), "") if cats else "",
                }

    return sorted(found.values(), key=lambda t: (-t["confidence"], t["name"]))


def tech_names(techs: List[Dict[str, Any]]) -> List[str]:
    return [t["name"] for t in techs]


# ── SSH HASSH ───────────────────────────────────────────────────────────────
def _ssh_namelists(kex_payload: bytes) -> List[str]:
    """
    Pull the algorithm name-lists out of an SSH_MSG_KEXINIT payload.

    Layout after the message byte: 16 random bytes, then ten
    uint32-length-prefixed comma-separated name-lists.
    """
    out: List[str] = []
    i = 0
    if i < len(kex_payload) and kex_payload[i] == 20:    # SSH_MSG_KEXINIT
        i += 1
    i += 16                                             # cookie
    for _ in range(10):
        if i + 4 > len(kex_payload):
            break
        (n,) = struct.unpack_from(">I", kex_payload, i)
        i += 4
        if n > len(kex_payload) or i + n > len(kex_payload):
            break
        out.append(kex_payload[i:i + n].decode("utf-8", "replace"))
        i += n
    return out


def compute_hassh(banner: str = "", kex_data: bytes = b"") -> str:
    """
    HASSH-Server fingerprint: md5 of

        kex;encryption;mac;compression

    taken from the server's SSH_MSG_KEXINIT. Returns '' without usable data.
    """
    if not kex_data:
        return ""
    raw = kex_data
    # strip the binary packet header (len + padding len) if present
    if len(raw) > 6 and raw[5:6] == b"\x14":
        raw = raw[5:]
    elif len(raw) > 1 and raw[0:1] != b"\x14":
        idx = raw.find(b"\x14")
        if idx != -1:
            raw = raw[idx:]
    lists = _ssh_namelists(raw)
    if len(lists) < 10:
        return ""
    kex, _hostkey, enc_cs, enc_sc, mac_cs, mac_sc, cmp_cs, cmp_sc = lists[:8]
    # server-to-client lists describe the server itself
    parts = ";".join([kex, enc_sc, mac_sc, cmp_sc])
    return hashlib.md5(parts.encode("utf-8", "replace")).hexdigest()


def grab_ssh_kex(ip: str, port: int = 22, timeout: float = 5.0) -> Tuple[str, bytes]:
    """Connect, read the SSH banner and the server's KEXINIT packet."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = b""
            while b"\n" not in banner and len(banner) < 512:
                chunk = s.recv(256)
                if not chunk:
                    break
                banner += chunk
            s.sendall(b"SSH-2.0-NorthHarv_1.0\r\n")
            blob = b""
            while len(blob) < 8192:
                chunk = s.recv(4096)
                if not chunk:
                    break
                blob += chunk
                if b"\x14" in blob and len(blob) > 64:
                    break
            return banner.decode("utf-8", "replace").strip(), blob
    except OSError:
        return "", b""


# ── JARM TLS fingerprinting ─────────────────────────────────────────────────
# A JARM fingerprint is 62 hex characters:
#   30 chars  = 10 probes x (2-char cipher id + 1-char TLS version id)
#   32 chars  = first 32 of sha256 over the per-probe extension strings
# Each probe is a deliberately odd ClientHello; servers differ in how they
# pick a cipher and which extensions they echo, and that pattern identifies
# the stack behind the socket.

# The full cipher set used by the probes, in the reference order.
_JARM_CIPHERS_ALL = [
    "0016", "0033", "0067", "c09e", "c0a2", "009e", "0039", "006b", "c09f",
    "c0a3", "009f", "0045", "00be", "0088", "00c4", "009a", "c008", "c009",
    "c023", "c0ac", "c0ae", "c02b", "c00a", "c024", "c0ad", "c0af", "c02c",
    "c072", "c073", "cca9", "1302", "1301", "cc14", "c007", "c012", "c013",
    "c027", "c02f", "c014", "c028", "c030", "c060", "c061", "c076", "c077",
    "cca8", "1305", "1304", "1303", "cc13", "c011", "000a", "002f", "003c",
    "c09c", "c0a0", "009c", "0035", "003d", "c09d", "c0a1", "009d", "0041",
    "00ba", "0084", "00c0", "0007", "0004", "0005",
]
# same list with the TLS 1.3 suites removed
_JARM_CIPHERS_NO13 = [c for c in _JARM_CIPHERS_ALL if not c.startswith("13")]

# cipher -> 2-char code, by position in the reference table (01-based, hex)
_JARM_CIPHER_CODES = {c: format(i + 1, "02x") for i, c in enumerate(_JARM_CIPHERS_ALL)}
_JARM_VERSION_CODES = {"0301": "4", "0302": "5", "0303": "6", "0304": "7", "0300": "3"}

_GREASE = ["0a0a", "1a1a", "2a2a", "3a3a", "4a4a", "5a5a", "6a6a", "7a7a",
           "8a8a", "9a9a", "aaaa", "baba", "caca", "dada", "eaea", "fafa"]

_ALPN_FULL = ["http/0.9", "http/1.0", "http/1.1", "spdy/1", "spdy/2", "spdy/3",
              "h2", "h2c", "http/2"]
_ALPN_RARE = ["http/0.9", "http/1.0", "spdy/1", "spdy/2", "spdy/3", "h2c", "http/2"]

# (tls_version, cipher_set, cipher_order, grease, alpn, support, ext_order)
JARM_PROBES = [
    ("0303", "ALL",   "FORWARD",     False, "ALPN", "1.2", "REVERSE"),
    ("0303", "ALL",   "REVERSE",     False, "ALPN", "1.2", "FORWARD"),
    ("0303", "ALL",   "TOP_HALF",    False, "ALPN", "NO",  "FORWARD"),
    ("0303", "ALL",   "BOTTOM_HALF", False, "RARE", "NO",  "FORWARD"),
    ("0303", "ALL",   "MIDDLE_OUT",  True,  "RARE", "NO",  "REVERSE"),
    ("0302", "ALL",   "FORWARD",     False, "ALPN", "NO",  "FORWARD"),
    ("0304", "ALL",   "FORWARD",     False, "ALPN", "1.3", "REVERSE"),
    ("0304", "ALL",   "REVERSE",     False, "ALPN", "1.3", "FORWARD"),
    ("0304", "NO13",  "FORWARD",     False, "ALPN", "NO",  "FORWARD"),
    ("0304", "ALL",   "MIDDLE_OUT",  True,  "ALPN", "1.3", "REVERSE"),
]


def _jarm_order(ciphers: List[str], how: str) -> List[str]:
    """Reorder the cipher list the way a given probe wants it."""
    if how == "FORWARD":
        return list(ciphers)
    if how == "REVERSE":
        return list(reversed(ciphers))
    if how == "TOP_HALF":
        half = ciphers[len(ciphers) // 2:]
        return half
    if how == "BOTTOM_HALF":
        return ciphers[:len(ciphers) // 2]
    if how == "MIDDLE_OUT":
        mid = len(ciphers) // 2
        out: List[str] = []
        if len(ciphers) % 2 == 1:
            out.append(ciphers[mid])
        for i in range(1, mid + 1):
            if mid + i < len(ciphers):
                out.append(ciphers[mid + i])
            if mid - i >= 0:
                out.append(ciphers[mid - i])
        return out
    return list(ciphers)


def _b(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr)


def _ext_block(host: str, probe) -> bytes:
    """Build the ClientHello extension block for one probe."""
    _ver, _set, _order, grease, alpn_kind, support, ext_order = probe
    exts: List[bytes] = []

    # server_name
    hb = host.encode("idna") if not _is_ip_literal(host) else b""
    if hb:
        sni = b"\x00\x00" + struct.pack(">H", len(hb) + 5) + struct.pack(">H", len(hb) + 3) \
            + b"\x00" + struct.pack(">H", len(hb)) + hb
        exts.append(sni)

    # extended_master_secret
    exts.append(_b("00170000"))
    # max_fragment_length
    exts.append(_b("0001000102"))
    # renegotiation_info
    exts.append(_b("ff01000100"))
    # supported_groups
    exts.append(_b("000a000a0008001d001700180019"))
    # ec_point_formats
    exts.append(_b("000b00020100"))
    # session_ticket
    exts.append(_b("00230000"))

    # ALPN
    protos = _ALPN_RARE if alpn_kind == "RARE" else _ALPN_FULL
    body = b"".join(bytes([len(p)]) + p.encode() for p in protos)
    exts.append(b"\x00\x10" + struct.pack(">H", len(body) + 2) + struct.pack(">H", len(body)) + body)

    # signature_algorithms
    exts.append(_b("000d00140012040308040401050308050501080606010201"))
    # key_share (x25519, zeroed key material)
    exts.append(_b("0033002b0029") + _b("001d0020") + bytes(32))
    # psk_key_exchange_modes
    exts.append(_b("002d00020101"))

    # supported_versions
    if support == "1.2":
        exts.append(_b("002b0007060304030303020301"))
    elif support == "1.3":
        exts.append(_b("002b0009080304030303020301") if not grease
                    else _b("002b000b0a") + _b(_GREASE[0]) + _b("03040303030203 01".replace(" ", "")))

    if ext_order == "REVERSE":
        exts.reverse()
    if grease:
        exts.insert(0, _b(_GREASE[0]) + b"\x00\x00")

    blob = b"".join(exts)
    return struct.pack(">H", len(blob)) + blob


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _jarm_hello(host: str, probe) -> bytes:
    """Assemble a full TLS record containing one JARM ClientHello."""
    ver, cset, order, grease, _alpn, _support, _ext = probe
    ciphers = _JARM_CIPHERS_ALL if cset == "ALL" else _JARM_CIPHERS_NO13
    ordered = _jarm_order(ciphers, order)
    cipher_bytes = b"".join(_b(c) for c in ordered)
    if grease:
        cipher_bytes = _b(_GREASE[0]) + cipher_bytes

    client_ver = b"\x03\x03" if ver == "0304" else _b(ver)
    body = client_ver + os.urandom(32)
    body += b"\x20" + os.urandom(32)                     # session id
    body += struct.pack(">H", len(cipher_bytes)) + cipher_bytes
    body += b"\x01\x00"                                  # compression: null
    body += _ext_block(host, probe)

    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16" + _b(ver if ver != "0304" else "0301") \
        + struct.pack(">H", len(handshake)) + handshake


def _parse_server_hello(data: bytes) -> Tuple[str, str, str]:
    """
    Pull (cipher_hex, version_hex, extension_signature) out of a ServerHello.

    Returns ('','','') for an alert, a closed socket or anything unparsable.
    """
    if not data or len(data) < 10:
        return "", "", ""
    if data[0] == 0x15:                       # TLS alert
        return "", "", ""
    if data[0] != 0x16 or data[5] != 0x02:    # not a handshake/ServerHello
        return "", "", ""
    try:
        version = data[9:11].hex()
        i = 11 + 32                           # version + random
        sid_len = data[i]
        i += 1 + sid_len
        cipher = data[i:i + 2].hex()
        i += 2 + 1                            # cipher + compression
        ext_total = struct.unpack_from(">H", data, i)[0]
        i += 2
        end = min(len(data), i + ext_total)
        types: List[str] = []
        alpn = ""
        supported_version = ""
        while i + 4 <= end:
            etype = data[i:i + 2].hex()
            elen = struct.unpack_from(">H", data, i + 2)[0]
            payload = data[i + 4:i + 4 + elen]
            types.append(etype)
            if etype == "0010" and len(payload) >= 4:     # ALPN
                alpn = payload[3:3 + payload[2]].decode("utf-8", "replace")
            if etype == "002b" and len(payload) >= 2:     # supported_versions
                supported_version = payload[:2].hex()
            i += 4 + elen
        if supported_version:
            version = supported_version
        ext_sig = "|".join([",".join(types), alpn])
        return cipher, version, ext_sig
    except (IndexError, struct.error):
        return "", "", ""


def jarm_fingerprint(ip: str, port: int = 443, timeout: float = 5.0) -> str:
    """
    Compute a JARM fingerprint by sending the ten probe ClientHellos.

    Returns the 62-character fingerprint. A host that never completes a
    handshake yields the all-zero JARM (62 zeros), which is what the
    reference tool reports for a non-TLS or filtered port.
    """
    cipher_part = ""
    ext_parts: List[str] = []

    for probe in JARM_PROBES:
        cipher = version = ext_sig = ""
        try:
            with socket.create_connection((ip, int(port)), timeout=timeout) as s:
                s.settimeout(timeout)
                s.sendall(_jarm_hello(ip, probe))
                data = b""
                while len(data) < 4096:
                    try:
                        chunk = s.recv(2048)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    data += chunk
                    if len(data) >= 10 and data[0] in (0x15, 0x16):
                        if len(data) >= 5:
                            need = 5 + struct.unpack_from(">H", data, 3)[0]
                            if len(data) >= need:
                                break
                cipher, version, ext_sig = _parse_server_hello(data)
        except (OSError, struct.error):
            pass

        if cipher:
            cipher_part += _JARM_CIPHER_CODES.get(cipher, "00")
            cipher_part += _JARM_VERSION_CODES.get(version, "0")
        else:
            cipher_part += "000"
        ext_parts.append(ext_sig)

    if cipher_part == "000" * 10 and not any(ext_parts):
        return "0" * 62

    digest = hashlib.sha256(",".join(ext_parts).encode()).hexdigest()[:32]
    return cipher_part + digest


def jarm_lookup(fingerprint: str) -> Dict[str, Any]:
    """Check a JARM hash against the known-C2 table from signatures.py."""
    fp = (fingerprint or "").lower()
    actor = SIG.MALICIOUS_JARM.get(fp, "")
    return {
        "jarm": fp,
        "is_malicious": bool(actor),
        "actor": actor,
        "known_hashes": len(SIG.MALICIOUS_JARM),
    }


# ── Risk scoring ────────────────────────────────────────────────────────────
# Services that should essentially never face the public internet.
RISKY_SERVICES = {
    "redis": 60, "mongodb": 60, "mongod": 60, "elasticsearch": 55,
    "memcached": 55, "telnet": 55, "vnc": 50, "rdp": 45, "ms-wbt-server": 45,
    "mysql": 40, "postgresql": 40, "mssql": 40, "ftp": 30, "smb": 45,
    "microsoft-ds": 45, "netbios-ssn": 35, "docker": 60, "kubernetes": 55,
}
RISKY_PORTS = {
    6379: 60, 27017: 60, 9200: 55, 11211: 55, 23: 55, 5900: 50, 3389: 45,
    3306: 40, 5432: 40, 1433: 40, 21: 30, 445: 45, 139: 35, 2375: 60, 2376: 55,
}


def compute_risk_score(row: Dict[str, Any], open_ports: Optional[int] = None) -> int:
    """
    NorthHarv Risk Score, 0-1000.

    The weighting is deliberately dominated by *evidence of real-world
    exploitation* rather than raw severity:

      CVSS severity          up to 400   (cvss_max x 40)
      In CISA KEV            up to 350   (actively exploited right now)
      EPSS probability       up to 200   (likelihood of exploitation)
      Dangerous exposure     up to  60   (unauthenticated datastores etc.)
      Port surface           up to  50   (more open ports, more to attack)
      TLS hygiene            up to  25   (self-signed / expired certificate)
      Long-standing exposure up to  30   (first seen over 90 days ago)

    So an internet-facing Redis with no known CVE lands near 70, while a
    host carrying a KEV-listed critical with high EPSS approaches 1000.
    """
    def _f(key, default=0.0):
        try:
            return float(row.get(key) or default)
        except (TypeError, ValueError):
            return default

    score = 0.0

    cvss = max(0.0, min(10.0, _f("cvss_max")))
    score += cvss * 40.0

    kev_raw = row.get("kev") or ""
    kev_list = [k for k in str(kev_raw).split(",") if k.strip()]
    if kev_list:
        score += 350.0 if len(kev_list) == 1 else min(350.0 + (len(kev_list) - 1) * 15.0, 400.0)

    epss = max(0.0, min(1.0, _f("epss_max")))
    score += epss * 200.0

    svc = str(row.get("service_name") or "").lower()
    try:
        port = int(row.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    exposure = max(RISKY_SERVICES.get(svc, 0), RISKY_PORTS.get(port, 0))
    score += exposure

    if open_ports is None:
        open_ports = 1
    score += min(int(open_ports), 10) * 5.0

    tls_raw = row.get("tls_json")
    tls: Dict[str, Any] = {}
    if isinstance(tls_raw, dict):
        tls = tls_raw
    elif tls_raw:
        try:
            tls = json.loads(tls_raw)
        except (ValueError, TypeError):
            tls = {}
    if tls:
        if tls.get("self_signed"):
            score += 15.0
        days = tls.get("days_to_expiry")
        if isinstance(days, (int, float)) and days < 0:
            score += 10.0

    first_seen = str(row.get("first_seen") or "")
    if first_seen:
        try:
            seen = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
            if seen.tzinfo is None:
                seen = seen.replace(tzinfo=timezone.utc)
            if (datetime.now(timezone.utc) - seen).days > 90:
                score += 30.0
        except ValueError:
            pass

    # a public web service is reachable by anyone with a browser
    if svc in ("http", "https") or port in (80, 443, 8080, 8443):
        score += 15.0

    return max(0, min(1000, int(round(score))))


def risk_breakdown(row: Dict[str, Any], open_ports: Optional[int] = None) -> Dict[str, Any]:
    """The same score, itemised — what /api/risk returns."""
    def _f(key, default=0.0):
        try:
            return float(row.get(key) or default)
        except (TypeError, ValueError):
            return default

    cvss = max(0.0, min(10.0, _f("cvss_max")))
    epss = max(0.0, min(1.0, _f("epss_max")))
    kev_list = [k for k in str(row.get("kev") or "").split(",") if k.strip()]
    svc = str(row.get("service_name") or "").lower()
    try:
        port = int(row.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    exposure = max(RISKY_SERVICES.get(svc, 0), RISKY_PORTS.get(port, 0))

    factors = [
        {"factor": "CVSS severity", "detail": f"cvss_max {cvss:.1f}",
         "points": round(cvss * 40.0), "max": 400},
        {"factor": "CISA KEV", "detail": f"{len(kev_list)} actively exploited CVE(s)" if kev_list else "not in KEV",
         "points": round(350.0 if len(kev_list) == 1 else (min(350.0 + (len(kev_list) - 1) * 15.0, 400.0) if kev_list else 0)),
         "max": 400},
        {"factor": "EPSS probability", "detail": f"{epss * 100:.1f}% chance of exploitation",
         "points": round(epss * 200.0), "max": 200},
        {"factor": "Dangerous exposure", "detail": svc or f"port {port}",
         "points": exposure, "max": 60},
        {"factor": "Port surface", "detail": f"{open_ports or 1} open port(s) on this IP",
         "points": min(int(open_ports or 1), 10) * 5, "max": 50},
    ]
    total = compute_risk_score(row, open_ports)
    return {
        "score": total,
        "band": risk_band(total),
        "factors": factors,
    }


def risk_band(score: int) -> str:
    if score >= 800:
        return "CRITICAL"
    if score >= 600:
        return "HIGH"
    if score >= 350:
        return "MEDIUM"
    if score >= 150:
        return "LOW"
    return "MINIMAL"


def recompute_all_risk() -> int:
    """Recalculate risk_score for every stored host. Returns rows updated."""
    conn = db()
    conn.row_factory = sqlite3.Row
    try:
        counts = {r[0]: r[1] for r in conn.execute(
            "SELECT ip, COUNT(*) FROM hosts GROUP BY ip")}
        rows = conn.execute("SELECT * FROM hosts").fetchall()
        updates = []
        for r in rows:
            d = dict(r)
            updates.append((compute_risk_score(d, counts.get(d["ip"], 1)),
                            d["ip"], d["port"]))
        conn.executemany("UPDATE hosts SET risk_score=? WHERE ip=? AND port=?", updates)
        conn.commit()
        return len(updates)
    finally:
        conn.close()


# ── Change intelligence ─────────────────────────────────────────────────────
CHANGE_FIELDS = ("service_name", "product", "version", "cves", "kev", "cvss_max")


def get_changes(since_hours: int = 24, limit: int = 500) -> List[Dict[str, Any]]:
    """
    What changed recently, by diffing each ip+port's two most recent
    observations. Emits: new_host, port_opened, service_changed, new_cve,
    severity_worsened and port_closed.
    """
    conn = db()
    conn.row_factory = sqlite3.Row
    out: List[Dict[str, Any]] = []
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=max(1, int(since_hours)))).isoformat()
        rows = conn.execute(
            "SELECT ip, port, scan_round, seen_at, record_json FROM observations"
            " ORDER BY ip, port, seen_at DESC").fetchall()

        grouped: Dict[Tuple[str, int], List[sqlite3.Row]] = {}
        for r in rows:
            grouped.setdefault((r["ip"], r["port"]), []).append(r)

        first_seen_ips = {r[0]: r[1] for r in conn.execute(
            "SELECT ip, MIN(first_seen) FROM hosts GROUP BY ip")}

        for (ip, port), obs in grouped.items():
            latest = obs[0]
            if latest["seen_at"] < cutoff:
                continue
            try:
                new = json.loads(latest["record_json"])
            except (ValueError, TypeError):
                continue

            if len(obs) == 1:
                kind = "new_host" if (first_seen_ips.get(ip) or "") >= cutoff else "port_opened"
                out.append({
                    "type": kind, "ip": ip, "port": port,
                    "field": "", "old": "", "new": new.get("service_name") or str(port),
                    "at": latest["seen_at"], "round": latest["scan_round"],
                })
                continue

            try:
                old = json.loads(obs[1]["record_json"])
            except (ValueError, TypeError):
                continue

            for f in CHANGE_FIELDS:
                o, n = old.get(f), new.get(f)
                if isinstance(o, list):
                    o = ",".join(map(str, o))
                if isinstance(n, list):
                    n = ",".join(map(str, n))
                o, n = ("" if o is None else str(o)), ("" if n is None else str(n))
                if o == n:
                    continue
                if f == "cves":
                    added = set(filter(None, n.split(","))) - set(filter(None, o.split(",")))
                    if not added:
                        continue
                    kind, o, n = "new_cve", o, ",".join(sorted(added))
                elif f == "kev":
                    if not n:
                        continue
                    kind = "new_cve"
                elif f == "cvss_max":
                    try:
                        if float(n or 0) <= float(o or 0):
                            continue
                    except ValueError:
                        continue
                    kind = "severity_worsened"
                else:
                    kind = "service_changed"
                out.append({
                    "type": kind, "ip": ip, "port": port, "field": f,
                    "old": o, "new": n, "at": latest["seen_at"],
                    "round": latest["scan_round"],
                })

        out.sort(key=lambda c: c["at"], reverse=True)
        return out[:limit]
    finally:
        conn.close()


def change_summary(changes: List[Dict[str, Any]]) -> Dict[str, int]:
    summary = {"new_host": 0, "port_opened": 0, "service_changed": 0,
               "new_cve": 0, "severity_worsened": 0, "port_closed": 0}
    for c in changes:
        summary[c["type"]] = summary.get(c["type"], 0) + 1
    return summary


# ── Relationship graph ──────────────────────────────────────────────────────
def related_hosts(ip: str) -> Dict[str, List[Dict[str, Any]]]:
    """Other hosts sharing this one's certificate CN, organisation or /24."""
    conn = db()
    conn.row_factory = sqlite3.Row
    try:
        me = conn.execute("SELECT * FROM hosts WHERE ip=? LIMIT 1", (ip,)).fetchone()
        if not me:
            return {"cert": [], "org": [], "subnet": []}
        me = dict(me)
        cn = ""
        try:
            cn = (json.loads(me.get("tls_json") or "{}") or {}).get("subject_cn", "")
        except (ValueError, TypeError):
            cn = ""
        org = ""
        try:
            org = (json.loads(me.get("geo_json") or "{}") or {}).get("org", "")
        except (ValueError, TypeError):
            org = ""

        def _rows(sql, params):
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

        cert_peers = _rows(
            "SELECT DISTINCT ip, port, product, risk_score FROM hosts"
            " WHERE ip != ? AND json_extract(tls_json,'$.subject_cn') = ? LIMIT 50",
            (ip, cn)) if cn else []
        org_peers = _rows(
            "SELECT DISTINCT ip, port, product, risk_score FROM hosts"
            " WHERE ip != ? AND json_extract(geo_json,'$.org') = ? LIMIT 50",
            (ip, org)) if org else []
        subnet_peers = []
        try:
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
            subnet_peers = _rows(
                "SELECT DISTINCT ip, port, product, risk_score FROM hosts"
                " WHERE ip != ? AND ip_int BETWEEN ? AND ? LIMIT 50",
                (ip, int(net.network_address), int(net.broadcast_address)))
        except ValueError:
            pass
        return {"cert": cert_peers, "org": org_peers, "subnet": subnet_peers,
                "cert_cn": cn, "org_name": org}
    finally:
        conn.close()


def build_graph(limit: int = 300) -> Dict[str, Any]:
    """Nodes + edges for the network map."""
    conn = db()
    conn.row_factory = sqlite3.Row
    try:
        rows = [dict(r) for r in conn.execute(
            "SELECT ip, port, product, version, service_name, cvss_max, kev,"
            " risk_score, tls_json, geo_json, cloud_provider, cves"
            " FROM hosts ORDER BY risk_score DESC LIMIT ?", (limit,)).fetchall()]
    finally:
        conn.close()

    nodes: Dict[str, Dict[str, Any]] = {}
    by_cn: Dict[str, List[str]] = {}
    by_org: Dict[str, List[str]] = {}
    by_net: Dict[str, List[str]] = {}

    for r in rows:
        ip = r["ip"]
        cvss = float(r.get("cvss_max") or 0)
        sev = ("CRITICAL" if cvss >= 9 else "HIGH" if cvss >= 7
               else "MEDIUM" if cvss >= 4 else "LOW" if cvss > 0 else "NONE")
        node = nodes.setdefault(ip, {
            "id": ip, "ip": ip, "risk": int(r.get("risk_score") or 0),
            "severity": sev, "product": r.get("product") or r.get("service_name") or "",
            "cloud": r.get("cloud_provider") or "", "ports": [],
            "kev": bool(r.get("kev")), "cves": len([c for c in str(r.get("cves") or "").split(",") if c]),
        })
        node["ports"].append(r["port"])
        node["risk"] = max(node["risk"], int(r.get("risk_score") or 0))
        if cvss >= 9 or sev == "CRITICAL":
            node["severity"] = "CRITICAL"

        try:
            cn = (json.loads(r.get("tls_json") or "{}") or {}).get("subject_cn", "")
        except (ValueError, TypeError):
            cn = ""
        if cn:
            by_cn.setdefault(cn, []).append(ip)
        try:
            org = (json.loads(r.get("geo_json") or "{}") or {}).get("org", "")
        except (ValueError, TypeError):
            org = ""
        if org:
            by_org.setdefault(org, []).append(ip)
        try:
            net = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            by_net.setdefault(net, []).append(ip)
        except ValueError:
            pass

    edges = []
    seen_edges = set()

    def _link(groups, reason, cap=6):
        for key, ips in groups.items():
            uniq = sorted(set(ips))
            if len(uniq) < 2 or len(uniq) > 60:
                continue
            for i, a in enumerate(uniq[:cap]):
                for b in uniq[i + 1:cap]:
                    k = (a, b, reason)
                    if k in seen_edges:
                        continue
                    seen_edges.add(k)
                    edges.append({"src": a, "dst": b, "reason": reason, "key": key})

    _link(by_cn, "ssl_cert")
    _link(by_org, "same_org", cap=5)
    _link(by_net, "same_subnet", cap=5)

    return {"nodes": list(nodes.values()), "edges": edges}
