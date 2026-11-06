"""
NorthHarv Web Application — FastAPI + WebSocket
Wraps the engine.core engine with a full web UI and REST API.
"""
import asyncio
import csv
import io
import json
import os
import random as _random
import sqlite3
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Ensure the project root is importable
_base = Path(__file__).parent.parent
sys.path.insert(0, str(_base))
from engine import core as engine  # noqa: E402
from engine import signatures  # noqa: E402

from fastapi import (
    BackgroundTasks, FastAPI, HTTPException, Query,
    WebSocket, WebSocketDisconnect, Request
)
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader

from northharv import wordlists  # noqa: E402

# ── Paths ──────────────────────────────────────────────────────────────────
UI_DIR = _base / "ui"

# ── FastAPI app ────────────────────────────────────────────────────────────
app = FastAPI(
    title="NorthHarv",
    description="Advanced Cyberspace Intelligence Platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

class _RevalidatingStatic(StaticFiles):
    """Serve the CSS/JS with no-cache so an edit shows up on the next load.

    The default headers let a browser hold a stylesheet or script in its
    memory cache and skip revalidation entirely, so an edited file keeps
    rendering the old page even through a hard reload. no-cache still
    allows a 304, which costs nothing over localhost.
    """

    def file_response(self, *args, **kwargs):
        resp = super().file_response(*args, **kwargs)
        resp.headers["Cache-Control"] = "no-cache, must-revalidate"
        return resp


app.mount("/static", _RevalidatingStatic(directory=str(UI_DIR / "static")), name="static")
# cache_size=0 avoids Python-3.14 hashability issues with Jinja2's LRU cache
_jinja_env = Environment(
    loader=FileSystemLoader(str(UI_DIR / "templates")),
    autoescape=True,
    cache_size=0,
)
templates = Jinja2Templates(env=_jinja_env)


def _asset_v(rel: str) -> str:
    """Modification stamp for a static file, used as a ?v= cache buster.

    No-cache headers alone were not enough: a stylesheet or script already
    sitting in the browser's cache kept being reused across hard reloads,
    so edits appeared to do nothing. Changing the URL whenever the file
    changes is the only version of this that cannot go stale.
    """
    try:
        return str(int((UI_DIR / "static" / rel).stat().st_mtime))
    except OSError:
        return "0"


_jinja_env.globals["asset_v"] = _asset_v

# ── Scan state ──────────────────────────────────────────────────────────────
# scan_id -> {"status","target","started","found","errors","round_id","name"}
active_scans: dict[str, dict[str, Any]] = {}
scan_queues: dict[str, asyncio.Queue] = {}

# enum_id -> {"status","target","wordlist","results":[...]}
active_enums: dict[str, dict[str, Any]] = {}

# ── Internet crawl state ─────────────────────────────────────────────────────
_crawl_meta: dict[str, Any] = {}
_crawl_task: Optional[asyncio.Task] = None
_crawl_stop_event: Optional[asyncio.Event] = None
_crawl_sse_queues: list[asyncio.Queue] = []

CRAWL_PARALLEL = int(os.getenv("CRAWL_PARALLEL", "8"))

# ── Discover feed state ───────────────────────────────────────────────────────
_discover_sse_queues: list[asyncio.Queue] = []

# ── Startup ─────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def _startup():
    engine.init_db()
    engine.GEO = engine.GeoDB()
    engine.CVE = engine.CveDB()
    _ensure_annotations_table()
    _auto_start_crawl()


def _ensure_annotations_table():
    conn = engine.db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS annotations (
            ip TEXT NOT NULL, port INTEGER NOT NULL,
            notes TEXT DEFAULT '', tags TEXT DEFAULT '',
            starred INTEGER DEFAULT 0, updated_at TEXT,
            PRIMARY KEY (ip, port)
        )""")
    conn.commit()
    conn.close()


# ── DB helpers ───────────────────────────────────────────────────────────────
def _db_dict(query: str, params=()) -> list[dict]:
    conn = engine.db()
    conn.row_factory = sqlite3.Row
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _db_one(query: str, params=()) -> Optional[dict]:
    rows = _db_dict(query, params)
    return rows[0] if rows else None


def _enrich_row(r: dict) -> dict:
    """Parse JSON blobs and add computed fields."""
    for f in ("tls_json", "geo_json"):
        if r.get(f):
            try:
                r[f] = json.loads(r[f])
            except Exception:
                r[f] = {}
    if r.get("cves"):
        r["cves_list"] = [c for c in r["cves"].split(",") if c]
    else:
        r["cves_list"] = []
    if r.get("kev"):
        r["kev_list"] = [c for c in r["kev"].split(",") if c]
    else:
        r["kev_list"] = []
    if r.get("cpe"):
        try:
            r["cpe_list"] = json.loads(r["cpe"])
        except Exception:
            r["cpe_list"] = []
    # severity label
    cvss = float(r.get("cvss_max") or 0)
    if cvss >= 9.0:
        r["severity"] = "CRITICAL"
    elif cvss >= 7.0:
        r["severity"] = "HIGH"
    elif cvss >= 4.0:
        r["severity"] = "MEDIUM"
    elif cvss > 0:
        r["severity"] = "LOW"
    else:
        r["severity"] = "NONE"
    return r


# ── API: Stats ────────────────────────────────────────────────────────────────
@app.get("/api/stats")
async def api_stats():
    conn = engine.db()
    out: dict[str, Any] = {}
    for t in ("hosts", "observations", "scan_rounds", "cve", "kev", "epss"):
        try:
            out[t] = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        except sqlite3.OperationalError:
            out[t] = 0
    # unique hosts (distinct IPs)
    try:
        out["unique_ips"] = conn.execute(
            "SELECT COUNT(DISTINCT ip) FROM hosts").fetchone()[0]
    except Exception:
        out["unique_ips"] = 0
    # critical hosts
    try:
        out["critical_hosts"] = conn.execute(
            "SELECT COUNT(DISTINCT ip) FROM hosts WHERE cvss_max >= 9").fetchone()[0]
    except Exception:
        out["critical_hosts"] = 0
    # kev hosts
    try:
        out["kev_hosts"] = conn.execute(
            "SELECT COUNT(DISTINCT ip) FROM hosts WHERE kev != ''").fetchone()[0]
    except Exception:
        out["kev_hosts"] = 0
    # top products
    try:
        out["top_products"] = [
            {"product": r[0], "count": r[1]}
            for r in conn.execute(
                "SELECT product, COUNT(*) c FROM hosts WHERE product != '' "
                "GROUP BY product ORDER BY c DESC LIMIT 10").fetchall()
        ]
    except Exception:
        out["top_products"] = []
    # top ports
    try:
        out["top_ports"] = [
            {"port": r[0], "count": r[1]}
            for r in conn.execute(
                "SELECT port, COUNT(*) c FROM hosts GROUP BY port ORDER BY c DESC LIMIT 10"
            ).fetchall()
        ]
    except Exception:
        out["top_ports"] = []
    # top countries
    try:
        out["top_countries"] = [
            {"country": r[0] or "Unknown", "count": r[1]}
            for r in conn.execute(
                "SELECT json_extract(geo_json,'$.country_code') cc, COUNT(*) c "
                "FROM hosts GROUP BY cc HAVING cc IS NOT NULL AND cc != '' "
                "ORDER BY c DESC LIMIT 10").fetchall()
        ]
    except Exception:
        out["top_countries"] = []
    # recent scan rounds
    try:
        cur = conn.execute(
            "SELECT * FROM scan_rounds ORDER BY round_id DESC LIMIT 5"
        )
        cols = [c[0] for c in cur.description]
        # NB: engine.db() leaves row_factory unset, so rows are plain tuples
        out["recent_rounds"] = [dict(zip(cols, r)) for r in cur.fetchall()]
    except Exception:
        out["recent_rounds"] = []
    # service distribution
    try:
        out["service_dist"] = [
            {"service": r[0] or "unknown", "count": r[1]}
            for r in conn.execute(
                "SELECT service_name, COUNT(*) c FROM hosts WHERE service_name != '' "
                "GROUP BY service_name ORDER BY c DESC LIMIT 12").fetchall()
        ]
    except Exception:
        out["service_dist"] = []
    conn.close()
    return out


# ── API: Search ───────────────────────────────────────────────────────────────
@app.get("/api/search")
async def api_search(
    q: str = Query("*", alias="q"),
    limit: int = Query(50, le=500),
    mode: str = Query("keyword"),
    page: int = Query(1, ge=1),
    facets: str = Query(""),
):
    offset = (page - 1) * limit
    if q == "*" or not q.strip():
        rows = _db_dict(
            "SELECT * FROM hosts ORDER BY kev DESC, cvss_max DESC, last_seen DESC "
            f"LIMIT {limit} OFFSET {offset}")
    elif mode == "fts":
        rows = engine.run_fts(q, limit)
    else:
        # A half-typed or malformed query is a bad request, not a server fault:
        # shlex raises on an unbalanced quote, and the port/asn/ip branches
        # raise on a value that is not a number or network.
        try:
            where, params = engine.parse_query(q)
        except ValueError as e:
            raise HTTPException(400, f"Could not parse query: {e}")
        rows = _db_dict(
            f"SELECT * FROM hosts WHERE {where} "
            f"ORDER BY kev DESC, cvss_max DESC, last_seen DESC "
            f"LIMIT {limit} OFFSET {offset}", params)
    rows = [_enrich_row(r) for r in rows]
    out: dict[str, Any] = {"query": q, "count": len(rows), "results": rows, "page": page}
    if facets:
        # facets are a nice-to-have: never fail the search over them
        out["facets"] = {}
        for f in facets.split(","):
            f = f.strip()
            if not f:
                continue
            try:
                out["facets"][f] = engine.run_facets(q if q != "*" else "", f, 20)
            except Exception as e:
                engine.log.warning("facet %r failed for query %r: %s", f, q, e)
    return out


# ── API: Host detail ──────────────────────────────────────────────────────────
@app.get("/api/host/{ip}")
async def api_host(ip: str):
    rows = _db_dict(
        "SELECT h.*, COALESCE(a.notes,'') notes, COALESCE(a.tags,'') tags, "
        "COALESCE(a.starred,0) starred "
        "FROM hosts h LEFT JOIN annotations a ON h.ip=a.ip AND h.port=a.port "
        "WHERE h.ip=? ORDER BY h.port", (ip,))
    if not rows:
        raise HTTPException(404, "Host not found")
    return [_enrich_row(r) for r in rows]


@app.get("/api/host/{ip}/{port}/history")
async def api_port_history(ip: str, port: int):
    rows = _db_dict(
        "SELECT scan_round, seen_at, record_json FROM observations "
        "WHERE ip=? AND port=? ORDER BY seen_at DESC LIMIT 200", (ip, port))
    for r in rows:
        try:
            r["record"] = json.loads(r["record_json"])
        except Exception:
            r["record"] = {}
    return rows


# ── API: CVE lookup ────────────────────────────────────────────────────────────
@app.get("/api/cve/{cve_id}")
async def api_cve(cve_id: str):
    cve_id = cve_id.upper()
    rows = _db_dict(
        "SELECT * FROM cve WHERE cve_id=? LIMIT 20", (cve_id,))
    if not rows:
        raise HTTPException(404, "CVE not found in local database — run sync-feeds first")
    kev = _db_one("SELECT * FROM kev WHERE cve_id=?", (cve_id,))
    epss = _db_one("SELECT * FROM epss WHERE cve_id=?", (cve_id,))
    # hosts affected
    affected = _db_dict(
        "SELECT DISTINCT ip, port, product, version, cvss_max FROM hosts "
        "WHERE cves LIKE ? LIMIT 100", (f"%{cve_id}%",))
    return {
        "cve_id": cve_id,
        "entries": rows,
        "kev": kev,
        "epss": epss,
        "affected_hosts": affected,
    }


# ── API: Facets ────────────────────────────────────────────────────────────────
@app.get("/api/facets")
async def api_facets(
    q: str = Query(""),
    fields: str = Query("port,country,product,service"),
    limit: int = Query(20, le=100),
):
    return {
        f: engine.run_facets(q, f.strip(), limit)
        for f in fields.split(",") if f.strip()
    }


# ── API: Annotations (notes / tags) ──────────────────────────────────────────
@app.post("/api/annotate")
async def api_annotate(request: Request):
    body = await request.json()
    ip = body.get("ip", "")
    port = int(body.get("port", 0))
    notes = body.get("notes", "")
    tags = body.get("tags", "")
    starred = int(bool(body.get("starred", False)))
    now = datetime.now(timezone.utc).isoformat()
    conn = engine.db()
    conn.execute(
        "INSERT INTO annotations (ip,port,notes,tags,starred,updated_at) VALUES (?,?,?,?,?,?) "
        "ON CONFLICT(ip,port) DO UPDATE SET notes=excluded.notes, tags=excluded.tags, "
        "starred=excluded.starred, updated_at=excluded.updated_at",
        (ip, port, notes, tags, starred, now))
    conn.commit()
    conn.close()
    return {"ok": True}


# ── API: Scan management ───────────────────────────────────────────────────────
@app.post("/api/scan")
async def api_scan_start(request: Request, background_tasks: BackgroundTasks):
    body = await request.json()
    cidr = body.get("cidr", "")
    ports_str = body.get("ports", "")
    name = body.get("name", cidr)
    if not cidr:
        raise HTTPException(400, "cidr required")
    # validate CIDR
    import ipaddress
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        raise HTTPException(400, str(e))
    ports = [int(x) for x in ports_str.split(",") if x.strip()] if ports_str else engine.TOP_PORTS
    scan_id = str(uuid.uuid4())[:8]
    q: asyncio.Queue = asyncio.Queue()
    scan_queues[scan_id] = q
    active_scans[scan_id] = {
        "id": scan_id,
        "name": name,
        "target": cidr,
        "ports": ports,
        "status": "queued",
        "started": datetime.now(timezone.utc).isoformat(),
        "finished": None,
        "found": 0,
        "error": None,
        "round_id": None,
    }
    background_tasks.add_task(_run_scan, scan_id, cidr, ports)
    return {"scan_id": scan_id, "status": "queued"}


async def _run_scan(scan_id: str, cidr: str, ports: list[int]):
    import ipaddress as _ip
    s = active_scans[scan_id]
    q = scan_queues[scan_id]
    s["status"] = "running"
    await q.put({"event": "started", "scan_id": scan_id, "target": cidr})
    try:
        nets = [_ip.ip_network(cidr, strict=False)]
        # Phase 1: discover
        await q.put({"event": "phase", "phase": "discovery", "target": cidr})
        found = await engine.discover_asyncio(cidr, ports, nets)
        await q.put({"event": "discovered", "count": len(found)})
        s["found"] = len(found)
        rid = engine.start_round(cidr, ports)
        s["round_id"] = rid
        # Phase 2: enrich
        await q.put({"event": "phase", "phase": "enrichment"})
        sem = asyncio.Semaphore(32)
        done_count = 0

        async def _w(ip, port):
            nonlocal done_count
            async with sem:
                await engine.enrich_and_store(ip, port, rid)
                done_count += 1
                if done_count % 10 == 0 or done_count == len(found):
                    await q.put({
                        "event": "progress",
                        "done": done_count,
                        "total": len(found),
                    })

        await asyncio.gather(*[_w(ip, p) for ip, p in found])
        engine.finish_round(rid, len(found))
        s["status"] = "done"
        s["finished"] = datetime.now(timezone.utc).isoformat()
        await q.put({"event": "done", "found": len(found), "round_id": rid})
    except Exception as e:
        s["status"] = "error"
        s["error"] = str(e)
        await q.put({"event": "error", "message": str(e)})


@app.get("/api/scans")
async def api_scans_list():
    return list(active_scans.values())


@app.get("/api/scan/{scan_id}")
async def api_scan_status(scan_id: str):
    if scan_id not in active_scans:
        raise HTTPException(404, "Scan not found")
    return active_scans[scan_id]


@app.delete("/api/scan/{scan_id}")
async def api_scan_cancel(scan_id: str):
    if scan_id not in active_scans:
        raise HTTPException(404, "Scan not found")
    active_scans[scan_id]["status"] = "cancelled"
    return {"ok": True}


# ── WebSocket: live scan feed ──────────────────────────────────────────────────
@app.websocket("/ws/scan/{scan_id}")
async def ws_scan(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    if scan_id not in scan_queues:
        await websocket.send_json({"event": "error", "message": "scan not found"})
        await websocket.close()
        return
    q = scan_queues[scan_id]
    try:
        while True:
            try:
                msg = await asyncio.wait_for(q.get(), timeout=30)
                await websocket.send_json(msg)
                if msg.get("event") in ("done", "error", "cancelled"):
                    break
            except asyncio.TimeoutError:
                await websocket.send_json({"event": "ping"})
    except WebSocketDisconnect:
        pass


# ── API: Path enumeration ──────────────────────────────────────────────────────
@app.post("/api/enumerate")
async def api_enum_start(request: Request, background_tasks: BackgroundTasks):
    body = await request.json()
    target_url = body.get("url", "")
    wordlist_key = body.get("wordlist", "web-common")
    threads = int(body.get("threads", 20))
    if not target_url:
        raise HTTPException(400, "url required")
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
    enum_id = str(uuid.uuid4())[:8]
    active_enums[enum_id] = {
        "id": enum_id,
        "url": target_url,
        "wordlist": wordlist_key,
        "status": "queued",
        "started": datetime.now(timezone.utc).isoformat(),
        "finished": None,
        "results": [],
        "total": 0,
        "checked": 0,
    }
    background_tasks.add_task(_run_enum, enum_id, target_url, wordlist_key, threads)
    return {"enum_id": enum_id}


async def _run_enum(enum_id: str, url: str, wordlist_key: str, threads: int):
    import urllib.request as ur
    e = active_enums[enum_id]
    e["status"] = "running"
    try:
        word_lines = await asyncio.to_thread(wordlists.lines, wordlist_key)
    except Exception as ex:
        e["status"] = "error"
        e["error"] = str(ex)
        return
    e["total"] = len(word_lines)
    sem = asyncio.Semaphore(threads)
    results = []

    async def _check(word: str):
        nonlocal results
        path = word.lstrip("/")
        full = url.rstrip("/") + "/" + path
        async with sem:
            try:
                def _req():
                    req = ur.Request(full, headers={"User-Agent": "NorthHarv/1.0"})
                    with ur.urlopen(req, timeout=5) as r:
                        return r.status, len(r.read(512)), r.headers.get("Content-Type", "")
                code, size, ctype = await asyncio.to_thread(_req)
                if code not in (404, 400):
                    results.append({
                        "url": full, "status": code, "size": size, "content_type": ctype
                    })
            except Exception:
                pass
            e["checked"] += 1

    await asyncio.gather(*[_check(w) for w in word_lines])
    e["results"] = sorted(results, key=lambda x: x["status"])
    e["status"] = "done"
    e["finished"] = datetime.now(timezone.utc).isoformat()


@app.get("/api/enum/{enum_id}")
async def api_enum_status(enum_id: str):
    if enum_id not in active_enums:
        raise HTTPException(404, "Enumeration not found")
    return active_enums[enum_id]


@app.get("/api/enums")
async def api_enums_list():
    return list(active_enums.values())


# ── API: Wordlists ─────────────────────────────────────────────────────────────
@app.get("/api/wordlists")
async def api_wordlists():
    return wordlists.all_status()


def _fetch_wordlist_bg(key: str):
    """Background fetch wrapper.

    The response has already been sent by the time this runs, so an exception
    here cannot reach the client — it only surfaces as "Exception in ASGI
    application". Log the failure and leave the wordlist marked not-loaded.
    """
    try:
        wordlists.fetch(key, True)
    except Exception as e:
        engine.log.warning("wordlist fetch failed (%s): %s", key, e)


@app.post("/api/wordlists/{key}/fetch")
async def api_wordlist_fetch(key: str, background_tasks: BackgroundTasks):
    if key not in wordlists.CATALOG:
        raise HTTPException(404, "Unknown wordlist")
    background_tasks.add_task(_fetch_wordlist_bg, key)
    return {"ok": True, "key": key, "message": "Download started"}


# ── API: Feed sync ─────────────────────────────────────────────────────────────
_sync_lock = threading.Lock()
_sync_status: dict[str, Any] = {"running": False, "last": None, "error": None}


@app.post("/api/feeds/sync")
async def api_feeds_sync(request: Request, background_tasks: BackgroundTasks):
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    years = body.get("years", [2023, 2024, 2025, 2026])
    force = bool(body.get("force", False))
    if _sync_status["running"]:
        raise HTTPException(409, "Sync already running")
    background_tasks.add_task(_run_sync, years, force)
    return {"ok": True, "message": "Sync started"}


def _run_sync(years, force):
    global _sync_status
    _sync_status["running"] = True
    _sync_status["error"] = None
    try:
        engine.sync_nvd(years, force)
        engine.sync_kev()
        engine.sync_epss()
        engine.CVE = engine.CveDB()  # reload
        _sync_status["last"] = datetime.now(timezone.utc).isoformat()
    except Exception as e:
        _sync_status["error"] = str(e)
    finally:
        _sync_status["running"] = False


def _feed_source_times() -> dict[str, Optional[str]]:
    """When each feed was last downloaded, from the cache files on disk.

    _sync_status only lives in this process: a CLI `sync-feeds` never touches
    it and a restart clears it, so the page reported "never" while the
    database held real data. The cache file mtimes are the durable record.
    """
    cache = Path(engine.NVD_CACHE_DIR)
    if not cache.is_absolute():
        cache = _base / cache

    def newest(*patterns: str) -> Optional[str]:
        times = []
        for pat in patterns:
            for p in cache.glob(pat):
                try:
                    times.append(p.stat().st_mtime)
                except OSError:
                    pass
        if not times:
            return None
        return datetime.fromtimestamp(max(times), timezone.utc).isoformat()

    return {
        "cve": newest("CVE-*.json.xz", "CVE-*.json.gz", "CVE-*.json"),
        "kev": newest("kev.json"),
        "epss": newest("epss.csv.gz"),
    }


@app.get("/api/feeds/status")
async def api_feeds_status():
    sources = _feed_source_times()
    stamps = [v for v in sources.values() if v]
    return {
        **_sync_status,
        "sources": sources,
        # fall back to the newest cached feed when this process has no record
        "last": _sync_status["last"] or (max(stamps) if stamps else None),
    }


# ── API: Export ────────────────────────────────────────────────────────────────
@app.get("/api/export")
async def api_export(
    q: str = Query(""),
    fmt: str = Query("json"),
    limit: int = Query(10000, le=100000),
):
    where, params = engine.parse_query(q) if q else ("1=1", [])
    rows = _db_dict(
        f"SELECT ip, port, service_name, product, version, banner, "
        f"http_title, http_server, cvss_max, epss_max, cves, kev, "
        f"geo_json, tls_json, first_seen, last_seen FROM hosts "
        f"WHERE {where} ORDER BY cvss_max DESC LIMIT {limit}", params)
    for r in rows:
        for f in ("geo_json", "tls_json"):
            if r.get(f):
                try:
                    r[f] = json.loads(r[f])
                except Exception:
                    pass
    if fmt == "csv":
        output = io.StringIO()
        fieldnames = ["ip", "port", "service_name", "product", "version",
                      "http_title", "cvss_max", "cves", "kev", "first_seen", "last_seen"]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=northharv_export.csv"},
        )
    return StreamingResponse(
        io.BytesIO(json.dumps(rows, default=str, indent=2).encode()),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=northharv_export.json"},
    )


# ── API: Diff rounds ──────────────────────────────────────────────────────────
@app.get("/api/diff")
async def api_diff(a: int = Query(...), b: int = Query(...)):
    conn = engine.db()
    conn.row_factory = sqlite3.Row
    a_rows = conn.execute(
        "SELECT ip, port, record_json FROM observations WHERE scan_round=? "
        "GROUP BY ip, port HAVING MAX(seen_at)", (a,)).fetchall()
    b_rows = conn.execute(
        "SELECT ip, port, record_json FROM observations WHERE scan_round=? "
        "GROUP BY ip, port HAVING MAX(seen_at)", (b,)).fetchall()
    conn.close()
    A = {(r["ip"], r["port"]): json.loads(r["record_json"]) for r in a_rows}
    B = {(r["ip"], r["port"]): json.loads(r["record_json"]) for r in b_rows}
    appeared = [{"ip": ip, "port": p, **B[(ip, p)]} for ip, p in set(B) - set(A)]
    disappeared = [{"ip": ip, "port": p, **A[(ip, p)]} for ip, p in set(A) - set(B)]
    changed = []
    for k in set(A) & set(B):
        pa, pb = A[k], B[k]
        diffs = [f for f in ("product", "version", "cves", "http_title", "service_name")
                 if (pa.get(f) or "") != (pb.get(f) or "")]
        if diffs:
            changed.append({"ip": k[0], "port": k[1], "fields": diffs,
                             "before": pa, "after": pb})
    return {"round_a": a, "round_b": b,
            "appeared": appeared, "disappeared": disappeared, "changed": changed}



# ── API: Fingerprinting ────────────────────────────────────────────────────
@app.get("/api/jarm")
async def api_jarm(ip: str = Query(...), port: int = Query(443)):
    """Run the ten JARM probes against a host and check the result."""
    fp = await asyncio.to_thread(engine.jarm_fingerprint, ip, port)
    out = engine.jarm_lookup(fp)
    out.update({"ip": ip, "port": port,
                "responded": fp != "0" * 62 and bool(fp)})
    return out


@app.get("/api/host/{ip}/{port}/jarm")
async def api_host_jarm(ip: str, port: int):
    fp = await asyncio.to_thread(engine.jarm_fingerprint, ip, port)
    out = engine.jarm_lookup(fp)
    out.update({"ip": ip, "port": port, "responded": fp != "0" * 62 and bool(fp)})
    # remember it for this host
    try:
        conn = engine.db()
        conn.execute("UPDATE hosts SET jarm=? WHERE ip=? AND port=?", (fp, ip, port))
        conn.commit()
        conn.close()
    except sqlite3.Error:
        pass
    return out


@app.get("/api/iconhash")
async def api_iconhash(url: str = Query(...)):
    """FOFA-compatible favicon hash for a URL."""
    h = await asyncio.to_thread(engine.fetch_icon_hash, url)
    return {"url": url, "icon_hash": h, "found": h != 0,
            "query": f"icon_hash:{h}" if h else ""}


@app.get("/api/host/{ip}/{port}/techs")
async def api_host_techs(ip: str, port: int):
    """Re-run technology detection against what we stored for this port."""
    row = _db_one("SELECT banner, http_headers, http_title, http_server"
                  " FROM hosts WHERE ip=? AND port=?", (ip, port))
    if not row:
        raise HTTPException(404, "Host/port not found")
    techs = engine.detect_technologies(
        banner=row.get("banner") or "",
        body=row.get("banner") or "",
        headers=row.get("http_headers") or "")
    return {"ip": ip, "port": port, "count": len(techs), "technologies": techs}


# ── API: Risk ──────────────────────────────────────────────────────────────
@app.get("/api/risk")
async def api_risk(ip: str = Query(...), port: int = Query(...)):
    row = _db_one("SELECT * FROM hosts WHERE ip=? AND port=?", (ip, port))
    if not row:
        raise HTTPException(404, "Host/port not found")
    open_ports = (_db_one("SELECT COUNT(*) c FROM hosts WHERE ip=?", (ip,)) or {}).get("c", 1)
    out = engine.risk_breakdown(row, open_ports)
    out.update({"ip": ip, "port": port, "stored": row.get("risk_score")})
    return out


# ── API: Change intelligence ───────────────────────────────────────────────
@app.get("/api/changes")
async def api_changes(since_hours: int = Query(24, ge=1, le=24 * 365)):
    changes = await asyncio.to_thread(engine.get_changes, since_hours)
    return {"since_hours": since_hours, "count": len(changes),
            "summary": engine.change_summary(changes), "changes": changes}


# ── API: Graph / timeline ──────────────────────────────────────────────────
@app.get("/api/graph")
async def api_graph(limit: int = Query(300, ge=10, le=2000)):
    return await asyncio.to_thread(engine.build_graph, limit)


@app.get("/api/timeline")
async def api_timeline():
    rows = _db_dict(
        "SELECT round_id, started_at, finished_at, target, ports, total_found"
        " FROM scan_rounds ORDER BY round_id")
    return rows


# ── API: Host relationships ────────────────────────────────────────────────
@app.get("/api/host/{ip}/related")
async def api_host_related(ip: str):
    return await asyncio.to_thread(engine.related_hosts, ip)


@app.get("/api/host/{ip}/whois")
async def api_host_whois(ip: str):
    """Organisation / network context assembled from what we have stored."""
    row = _db_one("SELECT geo_json, hostname, cloud_provider FROM hosts"
                  " WHERE ip=? LIMIT 1", (ip,))
    if not row:
        raise HTTPException(404, "Host not found")
    try:
        geo = json.loads(row.get("geo_json") or "{}") or {}
    except (ValueError, TypeError):
        geo = {}
    names = engine.hostnames_for(ip)
    domains = sorted({".".join(n.split(".")[-2:]) for n in names if n.count(".") >= 1})
    ports = [r["port"] for r in _db_dict(
        "SELECT port FROM hosts WHERE ip=? ORDER BY port", (ip,))]
    return {
        "ip": ip,
        "org": geo.get("org", ""),
        "asn": geo.get("asn", ""),
        "country": geo.get("country", ""),
        "country_code": geo.get("country_code", ""),
        "city": geo.get("city", ""),
        "region": geo.get("region", ""),
        "latitude": geo.get("latitude"),
        "longitude": geo.get("longitude"),
        "cloud_provider": row.get("cloud_provider") or "",
        "hostnames": names or ([row["hostname"]] if row.get("hostname") else []),
        "domains": domains,
        "open_ports": ports,
    }


# ── API: Explore ───────────────────────────────────────────────────────────
EXPLORE_CATEGORIES = [
    {"key": "databases", "title": "Databases", "icon": "i-database",
     "desc": "Exposed database engines of every flavour",
     "query": "port:3306,5432,27017,6379,9200,1521"},
    {"key": "web", "title": "Web Servers", "icon": "i-globe",
     "desc": "HTTP and HTTPS service banners",
     "query": "service:http"},
    {"key": "remote", "title": "Remote Access", "icon": "i-key",
     "desc": "SSH, RDP, VNC and telnet endpoints",
     "query": "port:22,3389,5900,23"},
    {"key": "critical", "title": "Critical Risk", "icon": "i-alert",
     "desc": "NorthHarv risk score of 900 or above",
     "query": "risk:900"},
    {"key": "kev", "title": "Actively Exploited", "icon": "i-flame",
     "desc": "Hosts matching the CISA KEV catalogue",
     "query": "kev:true"},
    {"key": "cloud", "title": "Cloud Infrastructure", "icon": "i-layers",
     "desc": "Workloads in AWS, GCP and Azure ranges",
     "query": "has:cloud"},
    {"key": "admin", "title": "Admin Panels", "icon": "i-monitor",
     "desc": "Login and dashboard pages",
     "query": "http.title:admin"},
    {"key": "selfsigned", "title": "Expired / Self-signed TLS", "icon": "i-certificate",
     "desc": "Certificates past expiry",
     "query": "ssl.expired:true"},
    {"key": "ics", "title": "Industrial Systems", "icon": "i-chip",
     "desc": "SCADA and building automation protocols",
     "query": "tag:ics"},
    {"key": "noauth", "title": "Unauthenticated Datastores", "icon": "i-dot-circle",
     "desc": "Redis and MongoDB with no access control",
     "query": "tag:no-auth"},
    {"key": "jenkins", "title": "Jenkins / CI", "icon": "i-bolt",
     "desc": "Continuous integration servers",
     "query": "tech:Jenkins"},
    {"key": "wordpress", "title": "WordPress Sites", "icon": "i-file-text",
     "desc": "Hosts running the WordPress stack",
     "query": "tech:WordPress"},
]

FEATURED_QUERIES = [
    {"label": "Critical CVSS with KEV", "query": "kev:true cvss:9.0"},
    {"label": "High EPSS probability", "query": "epss:0.9"},
    {"label": "Redis with no auth", "query": "port:6379"},
    {"label": "Self-signed certificates", "query": "ssl.selfsigned:true"},
    {"label": "Hosts with 3+ open ports", "query": "port.count:3"},
    {"label": "Cloudflare-fronted sites", "query": "http.waf:Cloudflare"},
    {"label": "Apache Tomcat managers", "query": "tech:Tomcat"},
    {"label": "Everything in Germany", "query": "country:DE"},
]


def _count_for(q: str) -> int:
    try:
        if not q or q.strip() == "*":
            row = _db_one("SELECT COUNT(*) c FROM hosts")
        else:
            where, params = engine.parse_query(q)
            row = _db_one(f"SELECT COUNT(*) c FROM hosts WHERE {where}", params)
        return int((row or {}).get("c", 0))
    except (ValueError, sqlite3.Error) as e:
        engine.log.warning("explore count failed for %r: %s", q, e)
        return 0


@app.get("/api/search/count")
async def api_search_count(q: str = Query("")):
    return {"query": q, "count": _count_for(q)}


@app.get("/api/explore")
async def api_explore():
    cats = []
    for c in EXPLORE_CATEGORIES:
        item = dict(c)
        item["count"] = _count_for(c["query"])
        cats.append(item)
    featured = []
    for f in FEATURED_QUERIES:
        item = dict(f)
        item["count"] = _count_for(f["query"])
        featured.append(item)
    totals = _db_one(
        "SELECT COUNT(*) ports, COUNT(DISTINCT ip) ips,"
        " SUM(CASE WHEN kev != '' THEN 1 ELSE 0 END) kev,"
        " SUM(CASE WHEN risk_score >= 800 THEN 1 ELSE 0 END) critical FROM hosts") or {}
    return {"categories": cats, "featured": featured, "totals": totals}


# ── API: Watchlist ─────────────────────────────────────────────────────────
@app.get("/api/watchlist")
async def api_watchlist_list():
    return _db_dict("SELECT id, pattern, label, type, created_at FROM watchlist"
                    " ORDER BY id DESC")


@app.get("/api/watchlist/hits")
async def api_watchlist_hits():
    rows = _db_dict("SELECT id, pattern, label, type FROM watchlist ORDER BY id DESC")
    for r in rows:
        r["hits"] = _count_for(r["pattern"])
    return rows


@app.post("/api/watchlist")
async def api_watchlist_add(request: Request):
    body = await request.json()
    pattern = (body.get("pattern") or "").strip()
    if not pattern:
        raise HTTPException(400, "pattern required")
    label = (body.get("label") or pattern).strip()
    kind = (body.get("type") or "query").strip()
    conn = engine.db()
    cur = conn.execute(
        "INSERT INTO watchlist (pattern, label, type, created_at) VALUES (?,?,?,?)",
        (pattern, label, kind, datetime.now(timezone.utc).isoformat()))
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return {"ok": True, "id": new_id, "pattern": pattern,
            "label": label, "type": kind, "hits": _count_for(pattern)}


@app.delete("/api/watchlist/{entry_id}")
async def api_watchlist_delete(entry_id: int):
    conn = engine.db()
    cur = conn.execute("DELETE FROM watchlist WHERE id=?", (entry_id,))
    conn.commit()
    gone = cur.rowcount
    conn.close()
    if not gone:
        raise HTTPException(404, "Watchlist entry not found")
    return {"ok": True, "deleted": entry_id}


# ── API: Signature databases ───────────────────────────────────────────────
@app.get("/api/daemon/status")
async def api_daemon_status():
    """What the continuous-scanning daemon is doing, for the dashboard."""
    try:
        return engine.daemon_status()
    except Exception as e:                       # never break the dashboard
        return {"status": "unknown", "running": False, "error": str(e)}


@app.get("/api/has-data")
async def api_has_data():
    """Cheap emptiness probe — every page asks this before it renders."""
    out = {"hosts": 0, "scan_rounds": 0, "daemon_running": False}
    try:
        conn = engine.db()
        for key, table in (("hosts", "hosts"), ("scan_rounds", "scan_rounds")):
            try:
                out[key] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            except sqlite3.OperationalError:
                out[key] = 0
        conn.close()
    except sqlite3.Error:
        pass
    try:
        out["daemon_running"] = bool(engine.daemon_status().get("running"))
    except Exception:
        pass
    out["empty"] = not out["hosts"]
    return out


@app.get("/api/signatures/status")
async def api_signatures_status():
    return signatures.status()


@app.post("/api/signatures/refresh")
async def api_signatures_refresh(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    force = bool((body or {}).get("force", False))
    started = signatures.refresh_async(force)
    return {"ok": True, "started": started,
            "message": "Refresh running in the background" if started
                       else "A refresh is already running"}


# ── API: Executive report ──────────────────────────────────────────────────
def _report_html() -> str:
    stats = _db_one(
        "SELECT COUNT(*) ports, COUNT(DISTINCT ip) ips,"
        " SUM(CASE WHEN kev != '' THEN 1 ELSE 0 END) kev,"
        " SUM(CASE WHEN risk_score >= 800 THEN 1 ELSE 0 END) critical,"
        " AVG(risk_score) avg_risk FROM hosts") or {}
    bands = _db_dict(
        "SELECT CASE WHEN risk_score>=800 THEN 'Critical'"
        " WHEN risk_score>=600 THEN 'High' WHEN risk_score>=350 THEN 'Medium'"
        " WHEN risk_score>=150 THEN 'Low' ELSE 'Minimal' END band,"
        " COUNT(*) n FROM hosts GROUP BY band ORDER BY n DESC")
    top = _db_dict(
        "SELECT ip, port, product, version, service_name, risk_score, cvss_max,"
        " kev, cves, hostname FROM hosts ORDER BY risk_score DESC LIMIT 10")
    cves = _db_dict(
        "SELECT cves FROM hosts WHERE cves != ''")
    counter: dict[str, int] = {}
    for r in cves:
        for c in str(r["cves"]).split(","):
            c = c.strip()
            if c:
                counter[c] = counter.get(c, 0) + 1
    top_cves = sorted(counter.items(), key=lambda kv: -kv[1])[:10]
    countries = _db_dict(
        "SELECT json_extract(geo_json,'$.country') c, COUNT(*) n FROM hosts"
        " GROUP BY c HAVING c IS NOT NULL ORDER BY n DESC LIMIT 10")
    techs = _db_dict("SELECT techs FROM hosts WHERE techs NOT IN ('', '[]')")
    tcount: dict[str, int] = {}
    for r in techs:
        try:
            for t in json.loads(r["techs"]):
                tcount[t] = tcount.get(t, 0) + 1
        except (ValueError, TypeError):
            pass
    top_techs = sorted(tcount.items(), key=lambda kv: -kv[1])[:12]

    def esc(s):
        return (str(s) if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def bar(n, total, colour):
        pct = (n / total * 100) if total else 0
        return (f'<div class="bar"><span style="width:{pct:.1f}%;background:{colour}"></span>'
                f'</div><span class="n">{n}</span>')

    total_ports = int(stats.get("ports") or 0)
    band_colours = {"Critical": "#f85149", "High": "#fb8500", "Medium": "#d29922",
                    "Low": "#58a6ff", "Minimal": "#3fb950"}

    rec = []
    if stats.get("kev"):
        rec.append(f"<li><strong>Patch the {stats['kev']} KEV-listed exposures first.</strong> "
                   "These vulnerabilities are being exploited in the wild today; "
                   "CISA requires remediation on a fixed deadline for federal agencies "
                   "and they are the highest-value targets on this estate.</li>")
    if stats.get("critical"):
        rec.append(f"<li><strong>Review the {stats['critical']} hosts scoring 800+.</strong> "
                   "Each combines a severe vulnerability with real exploitation likelihood.</li>")
    noauth = _count_for("tag:no-auth")
    if noauth:
        rec.append(f"<li><strong>Close {noauth} unauthenticated datastores.</strong> "
                   "Redis, MongoDB and Memcached expose full data access with no credentials "
                   "when reachable from the internet.</li>")
    expired = _count_for("ssl.expired:true")
    if expired:
        rec.append(f"<li><strong>Renew {expired} expired certificates.</strong> "
                   "Expired TLS breaks client trust and often signals unmanaged infrastructure.</li>")
    if not rec:
        rec.append("<li>No critical findings in the current dataset.</li>")

    rows_html = "".join(
        f"<tr><td class=mono><strong>{esc(h['ip'])}</strong>:{h['port']}</td>"
        f"<td>{esc(h.get('product') or h.get('service_name'))} {esc(h.get('version'))}</td>"
        f"<td class=mono>{esc(h.get('hostname'))}</td>"
        f"<td class=center>{esc(h.get('cvss_max'))}</td>"
        f"<td class=center>{'YES' if h.get('kev') else '—'}</td>"
        f"<td class='center score'>{h.get('risk_score')}</td></tr>"
        for h in top)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>NorthHarv Executive Report</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; padding:40px; font:15px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;
         color:#11161d; background:#f6f8fa; }}
  .sheet {{ max-width:960px; margin:0 auto; background:#fff; padding:44px 48px;
            border-radius:14px; box-shadow:0 2px 18px rgba(16,22,33,.09); }}
  header {{ border-bottom:3px solid #58a6ff; padding-bottom:18px; margin-bottom:28px; }}
  h1 {{ margin:0; font-size:1.8rem; letter-spacing:-.02em; }}
  h2 {{ margin:34px 0 12px; font-size:1.05rem; text-transform:uppercase;
        letter-spacing:.09em; color:#57606a; }}
  .sub {{ color:#57606a; font-size:.9rem; margin-top:6px; }}
  .kpis {{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin:22px 0 6px; }}
  .kpi {{ background:#f6f8fa; border:1px solid #d8dee4; border-radius:10px; padding:14px 16px; }}
  .kpi b {{ display:block; font-size:1.7rem; letter-spacing:-.03em; }}
  .kpi span {{ font-size:.7rem; text-transform:uppercase; letter-spacing:.1em; color:#57606a; }}
  table {{ width:100%; border-collapse:collapse; font-size:.86rem; margin-top:8px; }}
  th {{ text-align:left; font-size:.68rem; text-transform:uppercase; letter-spacing:.09em;
        color:#57606a; border-bottom:2px solid #d8dee4; padding:8px 10px; }}
  td {{ padding:8px 10px; border-bottom:1px solid #eaeef2; }}
  .mono {{ font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:.82rem; }}
  .center {{ text-align:center; }}
  .score {{ font-weight:700; color:#b3261e; }}
  .barrow {{ display:grid; grid-template-columns:150px 1fr 44px; gap:10px;
             align-items:center; margin-bottom:6px; font-size:.84rem; }}
  .bar {{ background:#eaeef2; border-radius:5px; height:10px; overflow:hidden; }}
  .bar span {{ display:block; height:100%; border-radius:5px; }}
  .n {{ text-align:right; font-family:ui-monospace,monospace; font-size:.78rem; color:#57606a; }}
  ul {{ padding-left:20px; }} li {{ margin-bottom:9px; }}
  footer {{ margin-top:34px; padding-top:16px; border-top:1px solid #d8dee4;
            font-size:.76rem; color:#57606a; }}
</style></head><body><div class="sheet">
<header>
  <h1>NorthHarv — Executive Report</h1>
  <div class="sub">Network intelligence summary · generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</div>
</header>

<h2>Executive summary</h2>
<div class="kpis">
  <div class="kpi"><b>{stats.get('ips') or 0}</b><span>Hosts</span></div>
  <div class="kpi"><b>{total_ports}</b><span>Open ports</span></div>
  <div class="kpi"><b style="color:#b3261e">{stats.get('kev') or 0}</b><span>KEV exposures</span></div>
  <div class="kpi"><b>{int(stats.get('avg_risk') or 0)}</b><span>Avg risk score</span></div>
</div>

<h2>Risk distribution</h2>
{''.join(f'<div class="barrow"><span>{esc(b["band"])}</span>{bar(b["n"], total_ports, band_colours.get(b["band"], "#58a6ff"))}</div>' for b in bands)}

<h2>Critical findings — highest risk hosts</h2>
<table><thead><tr><th>Host</th><th>Service</th><th>Hostname</th>
<th class=center>CVSS</th><th class=center>KEV</th><th class=center>Risk</th></tr></thead>
<tbody>{rows_html}</tbody></table>

<h2>Most common vulnerabilities</h2>
<table><thead><tr><th>CVE</th><th class=center>Affected hosts</th></tr></thead><tbody>
{''.join(f'<tr><td class=mono>{esc(c)}</td><td class=center>{n}</td></tr>' for c, n in top_cves) or '<tr><td colspan=2>None recorded</td></tr>'}
</tbody></table>

<h2>Technology distribution</h2>
{''.join(f'<div class="barrow"><span>{esc(t)}</span>{bar(n, total_ports, "#8b7cf8")}</div>' for t, n in top_techs) or '<p>No technologies fingerprinted yet.</p>'}

<h2>Geographic distribution</h2>
{''.join(f'<div class="barrow"><span>{esc(c["c"])}</span>{bar(c["n"], total_ports, "#39d0d8")}</div>' for c in countries) or '<p>No geolocation data.</p>'}

<h2>Recommendations</h2>
<ul>{''.join(rec)}</ul>

<footer>
  Generated by NorthHarv, self-hosted network intelligence. Risk scores combine
  CVSS severity, CISA KEV listing, EPSS exploitation probability and exposure
  characteristics on a 0–1000 scale.
</footer>
</div></body></html>"""


@app.get("/api/report")
async def api_report():
    html = await asyncio.to_thread(_report_html)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return StreamingResponse(
        io.BytesIO(html.encode("utf-8")),
        media_type="text/html",
        headers={"Content-Disposition":
                 f'attachment; filename=northharv-report-{stamp}.html'})


# ── Internet crawl ────────────────────────────────────────────────────────────

def _auto_start_crawl():
    """Called at startup: always start or resume the internet crawl."""
    try:
        st = engine.crawl_load_state()
        ports_str = st.get("ports", "")
        ports = [int(x) for x in ports_str.split(",") if x.strip()] if ports_str else engine.TOP_PORTS
        name = st.get("scan_name", "Internet Crawl")
        resume = bool(st.get("lcg_state") and st.get("lcg_start"))
        asyncio.get_event_loop().create_task(_launch_crawl(ports, name, resume=resume))
    except Exception as exc:
        engine.log.warning("crawl auto-start failed: %s", exc)


async def _broadcast_crawl(msg: dict) -> None:
    for q in list(_crawl_sse_queues):
        try:
            q.put_nowait(msg)
        except asyncio.QueueFull:
            pass


async def _broadcast_discover(hosts: list) -> None:
    if not hosts:
        return
    msg = {"event": "new_hosts", "hosts": hosts}
    for q in list(_discover_sse_queues):
        try:
            q.put_nowait(msg)
        except asyncio.QueueFull:
            pass


async def _launch_crawl(ports: list, name: str, resume: bool = False) -> None:
    global _crawl_task, _crawl_stop_event
    _crawl_stop_event = asyncio.Event()
    _crawl_task = asyncio.ensure_future(_run_crawl(ports, name, resume=resume))


async def _run_crawl(ports: list, name: str, resume: bool = False) -> None:
    global _crawl_meta
    import ipaddress as _ip

    db_state = engine.crawl_load_state()
    chunks_total = engine.crawl_total_chunks()

    if resume and db_state.get("lcg_state") and db_state.get("lcg_start"):
        lcg_state = int(db_state["lcg_state"])
        lcg_start = int(db_state["lcg_start"])
        chunks_done = int(db_state.get("chunks_done") or 0)
        started_at = db_state.get("started_at") or datetime.now(timezone.utc).isoformat()
    else:
        lcg_state = _random.randint(0, engine._CRAWL_LCG_M - 1)
        lcg_start = lcg_state
        chunks_done = 0
        started_at = datetime.now(timezone.utc).isoformat()

    _crawl_meta = {
        "status": "running",
        "chunks_done": chunks_done,
        "chunks_total": chunks_total,
        "current_chunk": "",
        "started_at": started_at,
    }

    engine.crawl_save_state(
        status="running",
        started_at=started_at,
        lcg_state=lcg_state,
        lcg_start=lcg_start,
        chunks_done=chunks_done,
        chunks_total=chunks_total,
        scan_name=name,
        ports=",".join(map(str, ports)),
    )

    await _broadcast_crawl({
        "event": "started",
        "chunks_total": chunks_total,
        "chunks_done": chunks_done,
        "resumed": resume,
    })

    loop = asyncio.get_event_loop()
    enrich_sem = asyncio.Semaphore(64)
    cycle_done = False

    async def _scan_chunk(cidr: str) -> int:
        """Scan one /24: masscan → asyncio fallback → enrich. Returns hosts_found."""
        nets = [_ip.ip_network(cidr, strict=False)]
        rid = engine.start_round(cidr, ports)
        try:
            found = await loop.run_in_executor(
                None, engine.discover_masscan, cidr, ports, nets, 1
            )
        except Exception:
            found = await engine.discover_asyncio(cidr, ports, nets)

        if found:
            async def _enrich(ip: str, port: int) -> None:
                async with enrich_sem:
                    await engine.enrich_and_store(ip, port, rid)
            await asyncio.gather(*[_enrich(ip, p) for ip, p in found])

        engine.finish_round(rid, len(found))

        if found and _discover_sse_queues:
            ips = list({ip for ip, _ in found})
            try:
                conn = engine.db()
                conn.row_factory = sqlite3.Row
                placeholders = ",".join("?" * len(ips))
                new_rows = conn.execute(
                    "SELECT ip, port, service_name, product, version, cvss_max, cves, last_seen, "
                    "json_extract(geo_json,'$.country_code') as country_code "
                    f"FROM hosts WHERE ip IN ({placeholders}) ORDER BY last_seen DESC",
                    ips,
                ).fetchall()
                conn.close()
                asyncio.ensure_future(_broadcast_discover([dict(r) for r in new_rows]))
            except Exception as _exc:
                engine.log.debug("discover broadcast failed: %s", _exc)

        return len(found)

    first = True
    while not _crawl_stop_event.is_set() and not cycle_done:  # type: ignore[union-attr]
        # Collect next CRAWL_PARALLEL CIDRs to scan in parallel
        batch: list[str] = []
        while len(batch) < CRAWL_PARALLEL:
            if not first and lcg_state == lcg_start:
                cycle_done = True
                break
            first = False
            cidr = engine.crawl_lcg_to_cidr(lcg_state)
            lcg_state = engine.crawl_lcg_step(lcg_state)
            if cidr is not None:
                batch.append(cidr)

        if not batch:
            break

        _crawl_meta["current_chunk"] = batch[0]

        results = await asyncio.gather(
            *[_scan_chunk(c) for c in batch],
            return_exceptions=True,
        )

        batch_found = sum(r for r in results if isinstance(r, int))
        chunks_done += len(batch)
        _crawl_meta["chunks_done"] = chunks_done

        engine.crawl_save_state(
            lcg_state=lcg_state,
            chunks_done=chunks_done,
            last_chunk=batch[-1],
            status="running",
        )

        await _broadcast_crawl({
            "event": "chunk_done",
            "cidr": batch[0],
            "chunks_done": chunks_done,
            "chunks_total": chunks_total,
            "hosts_found": batch_found,
        })

    if cycle_done:
        await _broadcast_crawl({"event": "cycle_complete", "chunks_done": chunks_done})

    final_status = "stopped"
    _crawl_meta["status"] = final_status
    engine.crawl_save_state(
        status=final_status,
        lcg_state=lcg_state,
        chunks_done=chunks_done,
    )
    await _broadcast_crawl({
        "event": "stopped",
        "chunks_done": chunks_done,
        "chunks_total": chunks_total,
    })


@app.post("/api/crawl/start")
async def api_crawl_start(request: Request):
    global _crawl_task, _crawl_stop_event
    if _crawl_task and not _crawl_task.done():
        raise HTTPException(409, "Crawl already running")
    body = await request.json()
    ports_str = body.get("ports", "")
    name = body.get("name", "Internet Crawl")
    ports = [int(x) for x in ports_str.split(",") if x.strip()] if ports_str else engine.TOP_PORTS

    db_state = engine.crawl_load_state()
    resume = bool(db_state.get("lcg_state") and db_state.get("lcg_start"))

    await _launch_crawl(ports, name, resume=resume)
    return {"ok": True, "status": "started", "resumed": resume}


@app.post("/api/crawl/stop")
async def api_crawl_stop():
    if _crawl_stop_event:
        _crawl_stop_event.set()
    return {"ok": True}


@app.get("/api/crawl/status")
async def api_crawl_status():
    db_state = engine.crawl_load_state()
    running = bool(_crawl_task and not _crawl_task.done())
    return {
        **db_state,
        **_crawl_meta,
        "running": running,
    }


@app.get("/api/crawl/stream")
async def api_crawl_stream(request: Request):
    q: asyncio.Queue = asyncio.Queue(maxsize=200)
    _crawl_sse_queues.append(q)

    async def gen():
        try:
            # Send current status immediately so the page knows whether crawl is active
            status_snapshot = {
                **engine.crawl_load_state(),
                **_crawl_meta,
                "event": "status",
                "running": bool(_crawl_task and not _crawl_task.done()),
            }
            yield f"data: {json.dumps(status_snapshot)}\n\n"
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=20)
                    yield f"data: {json.dumps(msg)}\n\n"
                    if msg.get("event") in ("stopped", "cycle_complete"):
                        break
                except asyncio.TimeoutError:
                    yield f"data: {json.dumps({'event': 'ping'})}\n\n"
        except (asyncio.CancelledError, GeneratorExit):
            pass
        finally:
            try:
                _crawl_sse_queues.remove(q)
            except ValueError:
                pass

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── API: Discover ─────────────────────────────────────────────────────────────
@app.get("/api/discover")
async def api_discover(offset: int = Query(0, ge=0), limit: int = Query(500, le=2000)):
    rows = _db_dict(
        "SELECT ip, port, service_name, product, version, cvss_max, cves, last_seen, "
        "json_extract(geo_json,'$.country_code') as country_code "
        "FROM hosts ORDER BY last_seen DESC "
        f"LIMIT {limit} OFFSET {offset}"
    )
    return {"hosts": rows, "offset": offset, "count": len(rows)}


@app.get("/api/discover/feed")
async def api_discover_feed(request: Request):
    q: asyncio.Queue = asyncio.Queue(maxsize=200)
    _discover_sse_queues.append(q)

    async def gen():
        try:
            yield f"data: {json.dumps({'event': 'connected'})}\n\n"
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=25)
                    yield f"data: {json.dumps(msg)}\n\n"
                except asyncio.TimeoutError:
                    yield f"data: {json.dumps({'event': 'ping'})}\n\n"
        except (asyncio.CancelledError, GeneratorExit):
            pass
        finally:
            try:
                _discover_sse_queues.remove(q)
            except ValueError:
                pass

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── UI Routes ─────────────────────────────────────────────────────────────────
def _resp(request: Request, name: str, ctx: dict = {}):
    """TemplateResponse helper compatible with both old and new Starlette."""
    try:
        return templates.TemplateResponse(request, name, ctx)
    except TypeError:
        return templates.TemplateResponse(name, {"request": request, **ctx})


@app.get("/")
async def ui_index(request: Request):
    return _resp(request, "index.html")


@app.get("/search")
async def ui_search(request: Request, q: str = Query("")):
    return _resp(request, "search.html", {"query": q})


@app.get("/host/{ip}")
async def ui_host(request: Request, ip: str):
    return _resp(request, "host.html", {"ip": ip})


@app.get("/scan")
async def ui_scan(request: Request):
    return _resp(request, "scan.html")


@app.get("/discover")
async def ui_discover(request: Request):
    return _resp(request, "discover.html")


@app.get("/feeds")
async def ui_feeds(request: Request):
    return _resp(request, "feeds.html")


@app.get("/wordlists")
async def ui_wordlists(request: Request):
    return _resp(request, "wordlists.html")


@app.get("/explore")
async def ui_explore(request: Request):
    return _resp(request, "explore.html")


@app.get("/changes")
async def ui_changes(request: Request):
    return _resp(request, "changes.html")


@app.get("/map")
async def ui_map(request: Request):
    return _resp(request, "map.html")


@app.get("/timeline")
async def ui_timeline(request: Request):
    return _resp(request, "timeline.html")


@app.get("/watchlist")
async def ui_watchlist(request: Request):
    return _resp(request, "watchlist.html")


@app.get("/cve/{cve_id}")
async def ui_cve(request: Request, cve_id: str):
    return _resp(request, "cve.html", {"cve_id": cve_id.upper()})


# ── Launch helper ──────────────────────────────────────────────────────────────
def start_server(port: int = 8080, host: str = "0.0.0.0"):
    import uvicorn
    print(f"\n  NorthHarv starting → http://localhost:{port}\n")
    uvicorn.run(app, host=host, port=port, log_level="info")
