#!/usr/bin/env python3
"""
Backward-compatibility shim.

The engine moved to engine/core.py. This module re-exports it so that older
entry points (`python demo.py ...`, `import demo`) keep working unchanged.

New code should use:

    from engine import core as engine
"""
import os
import sys

# make sure the project root is importable when this file is run directly
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

# Windows consoles default to a legacy code page when stdout is redirected;
# the engine prints box-drawing and arrow characters.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError, OSError):
        pass

from engine.core import *        # noqa: F401,F403,E402
from engine import core as _core  # noqa: E402

# re-export the private helpers a few callers still reach for
_download = _core._download
_parse_nvd_year = _core._parse_nvd_year
_cpe_parts = _core._cpe_parts
_cvss_from_nvd = _core._cvss_from_nvd

# keep `demo.X = ...` assignments visible to the engine itself
def __getattr__(name):
    return getattr(_core, name)


if __name__ == "__main__":
    _core.main()
