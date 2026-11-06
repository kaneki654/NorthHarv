#!/usr/bin/env python3
"""
NorthHarv — Advanced Cyberspace Intelligence Platform
Entry point for both CLI and web UI modes.

Usage:
  python run.py web [--port 8080]       Start the web UI
  python run.py init                    Initialize database
  python run.py sync-feeds              Sync NVD + CISA KEV + EPSS feeds
  python run.py scan --cidr X           Run a scan
  python run.py daemon --interval 24    Re-scan every allowlisted range, 24h apart
  python run.py query "product:nginx"   Search the database
  python run.py stats                   Show statistics

The daemon reads allowlist.txt on every cycle, so a range added later is
picked up at the next sweep without a restart. Each sweep opens its own scan
round, which is what the timeline and change detection compare. Its status
and next scheduled sweep appear on the dashboard.

IMPORTANT: You are responsible for scanning only networks you own or have
explicit written authorization to scan. Unauthorized scanning is illegal.
"""
import os
import sys

# On Windows stdout/stderr fall back to the legacy ANSI code page (cp1252 here)
# whenever they are not an interactive console — a pipe, a redirect to a file,
# or a parent process capturing output. Both the CLI (demo.py) and the web
# server (northharv/web.py) print characters that code page cannot represent
# (U+2192 "->" and U+2500 box drawing), so the first such print raised
# UnicodeEncodeError and killed the process before uvicorn ever started.
# Force UTF-8 on both streams at the single entry point so every command and
# every background task can print safely.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError, OSError):
        pass  # stream missing or not reconfigurable — leave it as it is

_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _here)


def main():
    args = sys.argv[1:]

    if not args:
        print(__doc__)
        sys.exit(0)

    cmd = args[0]

    if cmd == "web":
        port = 8080
        host = "0.0.0.0"
        for i, a in enumerate(args[1:], 1):
            if a in ("--port", "-p") and i < len(args):
                port = int(args[i + 1])
            elif a == "--host" and i < len(args):
                host = args[i + 1]
        from northharv.web import start_server
        start_server(port=port, host=host)
    else:
        # Delegate to the engine CLI for all other commands
        from engine import core as engine
        engine.main()


if __name__ == "__main__":
    main()
