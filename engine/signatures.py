"""
engine/signatures.py — external signature databases.

Three databases, all from public sources, fetched with stdlib urllib only:

  TECH   Wappalyzer technology fingerprints (a.json .. z.json)
  JARM   known C2 / malicious JARM hashes
  WAF    identYwaf web-application-firewall signatures

Each database has, in order of preference:
  1. a live download (primary URL, then a fallback URL),
  2. the on-disk cache in engine/cache/ (expires after 7 days),
  3. a small built-in table so detection still works offline.

Nothing here blocks import: the cache is read synchronously (fast) and a
refresh runs on a daemon thread. Set NORTHHARV_NO_SIG_REFRESH=1 to skip it.

Notes on the sources, as of this build:
  * wappalyzer/wappalyzer went closed-source and its raw technology files
    now 404, so the maintained community fork is used as the fallback. The
    file format is identical.
  * salesforce/jarm has no jarm_scans/ directory; the published C2 hash
    table in cedowens/C2-JARM is used instead.
  * identYwaf.py declares `SIGNATURES = {}` and loads the real data from
    data.json at runtime, so data.json is what gets parsed here.
"""
import json
import os
import re
import string
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CACHE_DIR = Path(__file__).parent / "cache"
WAPP_CACHE = CACHE_DIR / "wappalyzer"
JARM_CACHE = CACHE_DIR / "jarm_malicious.json"
WAF_CACHE = CACHE_DIR / "waf_signatures.json"
CATS_CACHE = CACHE_DIR / "wappalyzer_categories.json"

MAX_AGE = 7 * 86400          # a week
UA = {"User-Agent": "NorthHarv/1.0 (+signature-sync)"}
TIMEOUT = 45

# ── Source URLs ────────────────────────────────────────────────────────────
WAPP_PRIMARY = "https://raw.githubusercontent.com/wappalyzer/wappalyzer/master/src/technologies/{f}.json"
WAPP_FALLBACK = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/{f}.json"
CATS_PRIMARY = "https://raw.githubusercontent.com/wappalyzer/wappalyzer/master/src/categories.json"
CATS_FALLBACK = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/categories.json"

JARM_PRIMARY = "https://raw.githubusercontent.com/salesforce/jarm/master/jarm_scans/c2_jarm.txt"
JARM_FALLBACK = "https://raw.githubusercontent.com/cedowens/C2-JARM/main/README.md"

WAF_PRIMARY = "https://raw.githubusercontent.com/stamparm/identYwaf/master/data.json"
WAF_FALLBACK = "https://raw.githubusercontent.com/stamparm/identYwaf/master/identYwaf.py"

# ── Loaded state ───────────────────────────────────────────────────────────
# {tech_name: {"cats": [...], "implies": [...], "cpe": str,
#              "patterns": {field: [(regex_src, version_spec, confidence)]}}}
TECH_SIGNATURES: Dict[str, Dict[str, Any]] = {}
CATEGORIES: Dict[str, str] = {}
MALICIOUS_JARM: Dict[str, str] = {}
WAF_SIGNATURES: Dict[str, str] = {}

_compiled: Dict[Tuple[str, str], Optional[re.Pattern]] = {}
_lock = threading.Lock()
_refresh_thread: Optional[threading.Thread] = None
_last_refresh: Dict[str, Any] = {"running": False, "finished": None, "error": None}

# fields of a Wappalyzer entry that carry detection patterns, and what they
# should be matched against: "body", "headers" or "url"
PATTERN_FIELDS = {
    "html": "body",
    "scriptSrc": "body",
    "scripts": "body",
    "meta": "body",
    "text": "body",
    "headers": "headers",
    "cookies": "headers",
    "url": "url",
}

# Deliberately NOT in PATTERN_FIELDS:
#   dom — CSS selectors, not regexes. "a[href*='//secure.actblue.com/donate/']"
#         compiles as a valid regex meaning "the letter a, then one character
#         from that set", which matches the "al" in "internal" and fires on
#         almost any page. Evaluating these needs a DOM we do not build, so
#         treating them as regexes produced hundreds of false detections.
#   js   — JavaScript global variable names, only observable in a browser.
#   css  — regexes over fetched stylesheets, which the scanner does not fetch.

# ── Built-in fallbacks (used only with no network and no cache) ────────────
FALLBACK_TECH: Dict[str, Dict[str, Any]] = {
    "WordPress":    {"implies": ["PHP", "MySQL"], "cats": [1],
                     "patterns": {"body": [(r"/wp-(?:content|includes)/", None, 100),
                                           (r"<meta name=\"generator\" content=\"WordPress ([\d.]+)", r"\1", 100)]}},
    "Drupal":       {"implies": ["PHP"], "cats": [1],
                     "patterns": {"body": [(r"Drupal\.settings", None, 100)],
                                  "headers": [(r"X-Drupal-Cache", None, 100)]}},
    "Joomla":       {"implies": ["PHP"], "cats": [1],
                     "patterns": {"body": [(r"/media/jui/js/", None, 100)]}},
    "nginx":        {"implies": [], "cats": [22],
                     "patterns": {"headers": [(r"Server:\s*nginx(?:/([\d.]+))?", r"\1", 100)]}},
    "Apache":       {"implies": [], "cats": [22],
                     "patterns": {"headers": [(r"Server:\s*Apache(?:/([\d.]+))?", r"\1", 100)]}},
    "Microsoft-IIS": {"implies": [], "cats": [22],
                      "patterns": {"headers": [(r"Server:\s*Microsoft-IIS/([\d.]+)", r"\1", 100)]}},
    "Apache Tomcat": {"implies": ["Java"], "cats": [22],
                      "patterns": {"headers": [(r"Server:\s*Apache-Coyote", None, 100)]}},
    "Jenkins":      {"implies": ["Java"], "cats": [13],
                     "patterns": {"headers": [(r"X-Jenkins:\s*([\d.]+)", r"\1", 100)]}},
    "Grafana":      {"implies": [], "cats": [13],
                     "patterns": {"body": [(r"grafana[-.]app", None, 100)]}},
    "phpMyAdmin":   {"implies": ["PHP", "MySQL"], "cats": [13],
                     "patterns": {"body": [(r"phpMyAdmin", None, 100)]}},
}

# Public C2 JARM fingerprints. These are widely published values; the live
# table from cedowens/C2-JARM replaces this whenever it can be fetched.
FALLBACK_JARM: Dict[str, str] = {
    "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1": "Cobalt Strike",
    "07d19d12d21d21d07c42d43d000000f50d155305214cf247147c43c0f1a84f": "Cobalt Strike",
    "2ad2ad0002ad2ad00042d42d000000ad9bf51cc3f5a1e29eecb81d0c7b06eb": "Mythic",
    "2ad2ad16d2ad2ad22c42d42d00041d24a458a375eef0c576d23a7bab9a9fb1": "Metasploit",
    "29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38": "Metasploit",
    "29d3fd00029d29d00041d43d00041d58c80c29c6b5b2b3a37ca5a02d4a6cea": "Covenant",
    "2ad2ad0002ad2ad22c2ad2ad2ad2ad05a5a6c9e2d1b4b4e1f5a0a8ad1f63d4": "Deimos",
    "21d19d00021d21d21c21d19d21d21d1a5a4f2b4e5b1b3e9f9d5c7f6e0d8c1b": "PoshC2",
    "00000000000000000041d41d00041df8a1d9b9dd9a0a3f1b4c6e8a2b5d7f90": "Shad0w",
    "1dd40d40d00040d1dc1dd40d1dd40d3df2d6a0c2caaa0dc59908f0d3602943": "Sliver",
}

FALLBACK_WAF: Dict[str, str] = {
    "Cloudflare":        r"cloudflare|__cfduid|cf-ray|cf-cache-status",
    "AWS WAF":           r"awselb/|x-amzn-requestid|x-amz-cf-id",
    "Akamai":            r"akamaighost|akamai",
    "Imperva Incapsula": r"incap_ses|visid_incap|incapsula",
    "Sucuri":            r"sucuri|x-sucuri-id",
    "F5 BIG-IP":         r"big-?ip|bigipserver|x-wa-info",
    "Barracuda":         r"barra_counter_session|barracuda",
    "ModSecurity":       r"mod_security|modsecurity|not acceptable",
    "Fortinet FortiWeb": r"fortigate|fortiweb|fortinet",
    "Wordfence":         r"wordfence|generated by wordfence",
}


# ── Small helpers ──────────────────────────────────────────────────────────
def _fetch(url: str) -> Optional[bytes]:
    """GET a URL, returning None on any failure (never raises)."""
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.read()
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
        return None


def _fetch_first(*urls: str) -> Tuple[Optional[bytes], Optional[str]]:
    """Try each URL in order; return (body, url_that_worked)."""
    for u in urls:
        body = _fetch(u)
        if body:
            return body, u
    return None, None


def _age(path: Path) -> Optional[float]:
    try:
        return time.time() - path.stat().st_mtime
    except OSError:
        return None


def _stale(path: Path) -> bool:
    a = _age(path)
    return a is None or a > MAX_AGE


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / (path.name + ".part")
    try:
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _read_json(path: Path) -> Optional[Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def compiled(flavour: str, pattern: str) -> Optional[re.Pattern]:
    """Compile and memoise a signature regex; bad regexes are dropped."""
    key = (flavour, pattern)
    if key in _compiled:
        return _compiled[key]
    try:
        rx = re.compile(pattern, re.I)
    except re.error:
        rx = None
    _compiled[key] = rx
    return rx


# ── Wappalyzer parsing ─────────────────────────────────────────────────────
def _split_pattern(raw: str) -> Tuple[str, Optional[str], int]:
    r"""
    Split a Wappalyzer pattern into (regex, version_spec, confidence).

    The format is  regex\;version:\1\;confidence:50  — the tags are optional
    and may appear in either order.
    """
    parts = str(raw).split("\\;")
    regex = parts[0]
    version: Optional[str] = None
    confidence = 100
    for extra in parts[1:]:
        if extra.startswith("version:"):
            version = extra[len("version:"):]
        elif extra.startswith("confidence:"):
            try:
                confidence = max(0, min(100, int(extra[len("confidence:"):])))
            except ValueError:
                pass
    return regex, version, confidence


def _embeddable(regex: str) -> str:
    r"""Drop anchors from a pattern that is about to be embedded in another.

    A header or meta pattern such as ``^WordPress(?: ([\d.]+))?`` is anchored
    to the start of that *value*. Once it sits after ``content=["']?`` inside
    a larger regex, a leading ``^`` can never match and the whole signature
    goes dead. Same for a trailing ``$`` in the middle of a header blob.
    """
    if regex.startswith("^"):
        regex = regex[1:]
    if regex.endswith("$") and not regex.endswith("\\$"):
        regex = regex[:-1]
    return regex


def _as_list(v: Any, field: str = "") -> List[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    if isinstance(v, dict):
        # name -> pattern maps. How the pair appears in the response depends
        # on the field: a header reads "Name: value", a meta tag reads
        # <meta name="generator" content="WordPress 6.4">. Matching a meta
        # entry as if it were a header never fires, and matching a bare meta
        # name against the body fires on any page containing that word.
        out = []
        # a value may itself be a list of patterns for the same name
        pairs = []
        for name, pat in v.items():
            if isinstance(pat, list):
                pairs.extend((name, p) for p in pat)
            else:
                pairs.append((name, pat))
        for name, pat in pairs:
            regex, ver, conf = _split_pattern(str(pat or ""))
            regex = _embeddable(regex)
            esc = re.escape(str(name))
            if field == "meta":
                joined = (f"<meta[^>]+name=[\"']?{esc}[\"']?[^>]+content=[\"']?{regex}"
                          if regex else f"<meta[^>]+name=[\"']?{esc}[\"']?")
            elif field == "cookies":
                joined = (f"{esc}\\s*=\\s*{regex}" if regex
                          else f"[Ss]et-[Cc]ookie:[^\\n]*\\b{esc}\\s*=")
            else:
                joined = f"{esc}\\s*:?\\s*{regex}" if regex else esc
            tail = ""
            if ver:
                tail += "\\;version:" + ver
            if conf != 100:
                tail += "\\;confidence:" + str(conf)
            out.append(joined + tail)
        return out
    return [str(v)]


def _parse_wappalyzer(blob: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Turn one technologies/{letter}.json into our internal signature form."""
    out: Dict[str, Dict[str, Any]] = {}
    for name, entry in (blob or {}).items():
        if not isinstance(entry, dict):
            continue
        patterns: Dict[str, List[Tuple[str, Optional[str], int]]] = {}
        for field, target in PATTERN_FIELDS.items():
            if field not in entry:
                continue
            for raw in _as_list(entry[field], field):
                regex, ver, conf = _split_pattern(raw)
                if not regex:
                    continue
                patterns.setdefault(target, []).append((regex, ver, conf))
        implies = [str(i).split("\\;")[0] for i in _as_list(entry.get("implies"))]
        if not patterns:
            continue
        out[name] = {
            "cats": entry.get("cats") or [],
            "implies": implies,
            "cpe": entry.get("cpe") or "",
            "patterns": patterns,
        }
    return out


def _refresh_tech(force: bool) -> int:
    """Download the 26 technology files; returns how many techs are loaded."""
    WAPP_CACHE.mkdir(parents=True, exist_ok=True)
    merged: Dict[str, Dict[str, Any]] = {}

    for letter in string.ascii_lowercase:
        dest = WAPP_CACHE / f"{letter}.json"
        blob = None
        if force or _stale(dest):
            body, _url = _fetch_first(
                WAPP_PRIMARY.format(f=letter), WAPP_FALLBACK.format(f=letter))
            if body:
                try:
                    blob = json.loads(body)
                    _write_json(dest, blob)
                except ValueError:
                    blob = None
        if blob is None:
            blob = _read_json(dest)
        if isinstance(blob, dict):
            merged.update(_parse_wappalyzer(blob))

    # category names are a nicety; failure here is not fatal
    cats = None
    if force or _stale(CATS_CACHE):
        body, _ = _fetch_first(CATS_PRIMARY, CATS_FALLBACK)
        if body:
            try:
                cats = json.loads(body)
                _write_json(CATS_CACHE, cats)
            except ValueError:
                cats = None
    if cats is None:
        cats = _read_json(CATS_CACHE)
    if isinstance(cats, dict):
        with _lock:
            CATEGORIES.clear()
            for cid, meta in cats.items():
                CATEGORIES[str(cid)] = (meta or {}).get("name", "") if isinstance(meta, dict) else str(meta)

    with _lock:
        if merged:
            TECH_SIGNATURES.clear()
            TECH_SIGNATURES.update(merged)
        elif not TECH_SIGNATURES:
            TECH_SIGNATURES.update(FALLBACK_TECH)
        return len(TECH_SIGNATURES)


# ── JARM parsing ───────────────────────────────────────────────────────────
_JARM_RX = re.compile(r"\b([0-9a-f]{62})\b", re.I)


def _parse_jarm_text(text: str) -> Dict[str, str]:
    """
    Pull (hash -> actor) out of either a plain `hash actor` list or the
    markdown table published by cedowens/C2-JARM.
    """
    out: Dict[str, str] = {}
    for line in text.splitlines():
        m = _JARM_RX.search(line)
        if not m:
            continue
        h = m.group(1).lower()
        # strip the hash out; the actor is the first real cell that is left.
        # (a markdown row is "| Mythic | python 3 w/aiohttp | <hash> | <url> |",
        #  so the longest cell would wrongly pick the project URL)
        rest = line.replace(m.group(1), " ")
        cells = [c.strip(" |\t") for c in rest.split("|")] if "|" in rest else [rest.strip()]
        label = ""
        for c in cells:
            c = re.sub(r"\s+", " ", c).strip(" -|")
            if not c or set(c) <= set("-: "):
                continue
            if re.match(r"^(?:https?://|www\.)", c, re.I):
                continue
            label = c
            break
        out[h] = label or "Unknown C2"
    return out


def _refresh_jarm(force: bool) -> int:
    data = None
    if force or _stale(JARM_CACHE):
        body, _url = _fetch_first(JARM_PRIMARY, JARM_FALLBACK)
        if body:
            parsed = _parse_jarm_text(body.decode("utf-8", "replace"))
            if parsed:
                data = parsed
                _write_json(JARM_CACHE, data)
    if data is None:
        data = _read_json(JARM_CACHE)
    with _lock:
        if data:
            MALICIOUS_JARM.clear()
            MALICIOUS_JARM.update({str(k).lower(): str(v) for k, v in data.items()})
        elif not MALICIOUS_JARM:
            MALICIOUS_JARM.update(FALLBACK_JARM)
        return len(MALICIOUS_JARM)


# ── WAF parsing ────────────────────────────────────────────────────────────
def _parse_waf_blob(body: bytes) -> Dict[str, str]:
    """
    identYwaf data.json holds {"wafs": {key: {"name":..., "regex": ...}}}.
    The .py file only declares an empty SIGNATURES dict, so if we ever end up
    with the source file we scrape any `"name"`/`"regex"` pairs we can find.
    """
    text = body.decode("utf-8", "replace")
    try:
        blob = json.loads(text)
        wafs = blob.get("wafs") if isinstance(blob, dict) else None
        if isinstance(wafs, dict):
            out = {}
            for key, meta in wafs.items():
                if not isinstance(meta, dict):
                    continue
                rx = meta.get("regex") or ""
                name = meta.get("name") or meta.get("company") or key
                if rx:
                    out[str(name)] = str(rx)
            return out
    except ValueError:
        pass
    return {}


def _refresh_waf(force: bool) -> int:
    data = None
    if force or _stale(WAF_CACHE):
        body, _url = _fetch_first(WAF_PRIMARY, WAF_FALLBACK)
        if body:
            parsed = _parse_waf_blob(body)
            if parsed:
                data = parsed
                _write_json(WAF_CACHE, data)
    if data is None:
        data = _read_json(WAF_CACHE)
    with _lock:
        if data:
            WAF_SIGNATURES.clear()
            WAF_SIGNATURES.update({str(k): str(v) for k, v in data.items()})
        elif not WAF_SIGNATURES:
            WAF_SIGNATURES.update(FALLBACK_WAF)
        return len(WAF_SIGNATURES)


# ── Public API ─────────────────────────────────────────────────────────────
def load_cached() -> None:
    """Populate from disk only — no network. Safe to call at import."""
    merged: Dict[str, Dict[str, Any]] = {}
    for letter in string.ascii_lowercase:
        blob = _read_json(WAPP_CACHE / f"{letter}.json")
        if isinstance(blob, dict):
            merged.update(_parse_wappalyzer(blob))
    cats = _read_json(CATS_CACHE)
    jarm = _read_json(JARM_CACHE)
    waf = _read_json(WAF_CACHE)

    with _lock:
        TECH_SIGNATURES.clear()
        TECH_SIGNATURES.update(merged or FALLBACK_TECH)
        if isinstance(cats, dict):
            CATEGORIES.clear()
            for cid, meta in cats.items():
                CATEGORIES[str(cid)] = (meta or {}).get("name", "") if isinstance(meta, dict) else str(meta)
        MALICIOUS_JARM.clear()
        MALICIOUS_JARM.update({str(k).lower(): str(v) for k, v in (jarm or FALLBACK_JARM).items()})
        WAF_SIGNATURES.clear()
        WAF_SIGNATURES.update({str(k): str(v) for k, v in (waf or FALLBACK_WAF).items()})


def refresh_signatures(force: bool = False) -> Dict[str, Any]:
    """Download anything stale (or everything, with force=True)."""
    _last_refresh["running"] = True
    _last_refresh["error"] = None
    try:
        n_tech = _refresh_tech(force)
        n_jarm = _refresh_jarm(force)
        n_waf = _refresh_waf(force)
        _last_refresh["finished"] = time.time()
        return {"ok": True, "tech": n_tech, "jarm": n_jarm, "waf": n_waf}
    except Exception as e:                      # never let a refresh crash a caller
        _last_refresh["error"] = str(e)
        return {"ok": False, "error": str(e)}
    finally:
        _last_refresh["running"] = False


def refresh_async(force: bool = False) -> bool:
    """Kick off a refresh on a daemon thread. True if one was started."""
    global _refresh_thread
    if _refresh_thread is not None and _refresh_thread.is_alive():
        return False
    _refresh_thread = threading.Thread(
        target=refresh_signatures, args=(force,),
        name="nh-signature-refresh", daemon=True)
    _refresh_thread.start()
    return True


def _fmt_age(path: Path) -> Optional[float]:
    a = _age(path)
    return round(a, 1) if a is not None else None


def status() -> Dict[str, Any]:
    """Counts, cache ages and source info — what /api/signatures/status serves."""
    wapp_files = sorted(WAPP_CACHE.glob("*.json")) if WAPP_CACHE.exists() else []
    wapp_age = min((_age(p) or 0) for p in wapp_files) if wapp_files else None
    return {
        "running": _last_refresh["running"],
        "error": _last_refresh["error"],
        "max_age_days": MAX_AGE // 86400,
        "databases": {
            "tech": {
                "count": len(TECH_SIGNATURES),
                "cached_files": len(wapp_files),
                "age_seconds": round(wapp_age, 1) if wapp_age is not None else None,
                "stale": wapp_age is None or wapp_age > MAX_AGE,
                "source": "Wappalyzer fingerprints",
                "fallback": len(TECH_SIGNATURES) == len(FALLBACK_TECH) and not wapp_files,
            },
            "jarm": {
                "count": len(MALICIOUS_JARM),
                "age_seconds": _fmt_age(JARM_CACHE),
                "stale": _stale(JARM_CACHE),
                "source": "C2 JARM hash list",
                "fallback": not JARM_CACHE.exists(),
            },
            "waf": {
                "count": len(WAF_SIGNATURES),
                "age_seconds": _fmt_age(WAF_CACHE),
                "stale": _stale(WAF_CACHE),
                "source": "identYwaf signatures",
                "fallback": not WAF_CACHE.exists(),
            },
        },
    }


# ── Import-time bootstrap ──────────────────────────────────────────────────
load_cached()
if os.getenv("NORTHHARV_NO_SIG_REFRESH", "") not in ("1", "true", "yes"):
    try:
        refresh_async(False)
    except RuntimeError:
        pass
