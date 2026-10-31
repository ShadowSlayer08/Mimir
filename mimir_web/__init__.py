"""mimir_web — the operator-workflow web app.

Serves auth, engagement management, scope / ROE editing, scan staging,
live result view, and the (pre-existing) read-only engagement viewer.
Stdlib-only HTTP server + Fernet-signed session cookies + SQLite store.

Entry point:  `mimir-ops` (defined in pyproject.toml)
"""
from .app import main, serve     # noqa: F401
