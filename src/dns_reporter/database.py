from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path


BLOCKED_STATUSES = frozenset({1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18})


class SourceUnavailable(RuntimeError):
    """Raised when a configured read-only data source cannot be opened."""


@contextmanager
def connect_readonly(path: Path) -> Iterator[sqlite3.Connection]:
    """Open an existing SQLite database without permission to create or write."""
    try:
        resolved = path.resolve()
        available = resolved.is_file()
    except OSError as exc:
        raise SourceUnavailable(f"Data source unavailable: {path.name}") from exc
    if not available:
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
        # The container intentionally has a very small read-only filesystem and
        # /tmp.  Pi-hole inventory queries need a temporary B-tree; keeping it in
        # process memory avoids a misleading SQLITE_FULL when /tmp fills up.
        connection.execute("PRAGMA temp_store = MEMORY")
    except sqlite3.Error as exc:
        raise SourceUnavailable(
            f"Unable to open data source: {resolved.name}"
        ) from exc
    try:
        yield connection
    finally:
        connection.close()
