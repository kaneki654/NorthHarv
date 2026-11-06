"""
Wordlist manager — fetches legitimate SecLists wordlists from GitHub.
SecLists: https://github.com/danielmiessler/SecLists (MIT License)
CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""
import os
import urllib.request
from pathlib import Path

WORDLISTS_DIR = Path(__file__).parent.parent / "wordlists_cache"

CATALOG: dict[str, dict] = {
    "web-common": {
        "name": "Web Content — Common",
        "desc": "~4700 common web paths (SecLists)",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "category": "web",
    },
    "web-big": {
        "name": "Web Content — Big",
        "desc": "~20k web paths (SecLists)",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt",
        "category": "web",
    },
    "web-raft-dirs": {
        "name": "Web Directories — RAFT Large",
        "desc": "~62k directory names (SecLists)",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt",
        "category": "web",
    },
    "web-api": {
        "name": "API Endpoints",
        "desc": "Common REST API endpoint paths (SecLists)",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
        "category": "web",
    },
    # NB: SecLists has no "top 1000" DNS list — the smallest tier is 5000.
    # Both entries previously pointed at subdomains-top1million-5000.txt, so
    # the two cached files were byte-identical. They are now a real small/large
    # pair, mirroring the web-common / web-big tiering above.
    "subdomains-top5k": {
        "name": "Subdomains — Top 5000",
        "desc": "5000 most common subdomain names (SecLists)",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
        "category": "dns",
    },
    "subdomains-top20k": {
        "name": "Subdomains — Top 20000",
        "desc": "20000 most common subdomain names (SecLists)",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
        "category": "dns",
    },
    "default-creds": {
        "name": "Default Credentials",
        "desc": "Common default usernames:passwords (SecLists)",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/default-passwords.csv",
        "category": "auth",
    },
    "user-agents": {
        "name": "User-Agent Strings",
        "desc": "Common browser/bot user agents (SecLists)",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/User-Agents/UserAgents.fuzz.txt",
        "category": "misc",
    },
}


def local_path(key: str) -> Path:
    return WORDLISTS_DIR / f"{key}.txt"


def is_cached(key: str) -> bool:
    return local_path(key).exists()


def fetch(key: str, force: bool = False) -> Path:
    """Download wordlist and cache locally. Returns local path."""
    if key not in CATALOG:
        raise ValueError(f"Unknown wordlist: {key}")
    p = local_path(key)
    if p.exists() and not force:
        return p
    WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)
    entry = CATALOG[key]
    url = entry["url"]
    req = urllib.request.Request(url, headers={"User-Agent": "NorthHarv/1.0"})
    # Write to a sibling temp file and swap it in atomically. Writing straight
    # to `p` makes the file exist from the moment the download starts, so
    # status() reports the list as loaded with 0 entries while it is still
    # downloading — and leaves a truncated file marked loaded if it fails.
    tmp = p.parent / (p.name + ".part")
    try:
        with urllib.request.urlopen(req, timeout=60) as r, open(tmp, "wb") as f:
            while chunk := r.read(1 << 20):
                f.write(chunk)
        os.replace(tmp, p)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return p


def lines(key: str) -> list[str]:
    """Return lines from a wordlist (fetching if needed)."""
    p = fetch(key)
    return [l.strip() for l in p.read_text(encoding="utf-8", errors="ignore").splitlines()
            if l.strip() and not l.startswith("#")]


def status(key: str) -> dict:
    p = local_path(key)
    info = dict(CATALOG[key])
    info["key"] = key
    info["cached"] = p.exists()
    if p.exists():
        info["size_bytes"] = p.stat().st_size
        info["line_count"] = sum(1 for _ in p.open(encoding="utf-8", errors="ignore"))
    return info


def all_status() -> list[dict]:
    return [status(k) for k in CATALOG]
