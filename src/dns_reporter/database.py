from __future__ import annotations

import sqlite3
from pathlib import Path


BLOCKED_STATUSES = frozenset({1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18})


class SourceUnavailable(RuntimeError):
    """Raised when a configured read-only data source cannot be opened."""


def connect_readonly(path: Path) -> sqlite3.Connection:
    """Open an existing SQLite database without permission to create or write."""
    resolved = path.resolve()
    if not resolved.is_file():
        raise SourceUnavailable(f"Data source unavailable: {resolved.name}")

    try:
        connection = sqlite3.connect(
            f"{resolved.as_uri()}?mode=ro",
            uri=True,
            timeout=1.0,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA busy_timeout = 1000")
        return connection
    except sqlite3.Error as exc:
        raise SourceUnavailable(
            f"Unable to open data source: {resolved.name}"
        ) from exc
