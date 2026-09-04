from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Iterable, Iterator, Mapping


EXPORT_COLUMNS = (
    "query_id", "timestamp_local", "timestamp_utc", "timestamp_epoch", "timezone",
    "canonical_device_id", "device_name", "device_identity_confidence", "client_key",
    "client_ip", "domain", "service_id", "service_name", "company", "category",
    "infrastructure_provider", "classification_confidence", "classification_rule_id",
    "classification_version", "query_type_raw", "query_type_label", "status_raw",
    "status_label", "blocked", "reply_type_raw", "reply_type_label", "reply_time",
    "forward", "list_id", "signal_ids", "signal_types", "report_start_local",
    "report_end_local", "baseline_start_local", "baseline_end_local",
)


def stream_csv(rows: Iterable[Mapping[str, object]]) -> Iterator[bytes]:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(EXPORT_COLUMNS)
    yield b"\xef\xbb\xbf" + _take(buffer)
    for row in rows:
        writer.writerow([_spreadsheet_safe(row.get(column)) for column in EXPORT_COLUMNS])
        yield _take(buffer)


def stream_jsonl(rows: Iterable[Mapping[str, object]]) -> Iterator[bytes]:
    for row in rows:
        ordered = {column: row.get(column) for column in EXPORT_COLUMNS}
        yield (json.dumps(ordered, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def safe_fragment(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:48] or "queries"


def _take(buffer: io.StringIO) -> bytes:
    value = buffer.getvalue().encode("utf-8")
    buffer.seek(0)
    buffer.truncate(0)
    return value


def _spreadsheet_safe(value: object) -> object:
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value
