# AstraNexus App Package
import sys
import types
from pathlib import Path

# ==============================================================================
# Dynamic Environment & Import Resolution Bootstrap
# Resolves package hierarchy whether deployed via:
# - Monorepo root (Local dev & test runners: `from backend.app...`)
# - Standalone directory / Serverless container (/var/task where `backend/` is root)
# ==============================================================================
_app_dir = Path(__file__).resolve().parent
_backend_dir = _app_dir.parent

for _p in [str(_backend_dir), str(_backend_dir.parent), str(_app_dir)]:
    if _p and _p not in sys.path:
        sys.path.insert(0, _p)

if "backend" not in sys.modules:
    try:
        import backend  # noqa: F401
    except ImportError:
        _backend_pkg = types.ModuleType("backend")
        _backend_pkg.__path__ = [str(_backend_dir)]
        sys.modules["backend"] = _backend_pkg

if "app" in sys.modules and "backend.app" not in sys.modules:
    sys.modules["backend.app"] = sys.modules["app"]
    if hasattr(sys.modules.get("backend"), "__dict__"):
        sys.modules["backend"].app = sys.modules["app"]

