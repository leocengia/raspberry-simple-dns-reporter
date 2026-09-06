from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping
from datetime import datetime
from zoneinfo import ZoneInfo


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

PRESENCE_COLUMNS = (
    "event_id", "timestamp_local", "timestamp_epoch", "timezone",
    "canonical_device_id", "device_name", "state", "source", "confidence",
    "detail", "report_start_local", "report_end_local",
)

LLM_SCHEMA_VERSION = "homeshield-dns-llm-v1"
LLM_ACTIVITY_BUCKET_SECONDS = 300
LLM_CHUNK_HOURS = 6
ROME = ZoneInfo("Europe/Rome")


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


def stream_presence_csv(rows: Iterable[Mapping[str, object]]) -> Iterator[bytes]:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(PRESENCE_COLUMNS)
    yield b"\xef\xbb\xbf" + _take(buffer)
    for row in rows:
        writer.writerow([_spreadsheet_safe(row.get(column)) for column in PRESENCE_COLUMNS])
        yield _take(buffer)


def stream_presence_jsonl(rows: Iterable[Mapping[str, object]]) -> Iterator[bytes]:
    for row in rows:
        ordered = {column: row.get(column) for column in PRESENCE_COLUMNS}
        yield (json.dumps(ordered, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def stream_llm_markdown(
    report: Mapping[str, object],
    rows: Iterable[Mapping[str, object]],
    *,
    scope: str,
    label: str,
) -> Iterator[bytes]:
    """Serialize a compact, self-describing DNS evidence bundle for LLM review.

    Raw queries are grouped into fixed five-minute activity buckets by device and
    classified service. Exact first/last query timestamps and top domains remain
    available, while repeated DNS chatter does not consume one line per query.
    """
    activity: dict[tuple[int, str, str], dict[str, object]] = {}
    query_count = 0
    for row in rows:
        query_count += 1
        epoch = float(row.get("timestamp_epoch") or 0)
        bucket = int(epoch // LLM_ACTIVITY_BUCKET_SECONDS) * LLM_ACTIVITY_BUCKET_SECONDS
        device_id = str(row.get("canonical_device_id") or "unknown")
        service_id = str(row.get("service_id") or "unknown")
        key = (bucket, device_id, service_id)
        item = activity.get(key)
        if item is None:
            item = {
                "bucket_epoch": bucket,
                "first_epoch": epoch,
                "last_epoch": epoch,
                "device_id": device_id,
                "device_name": str(row.get("device_name") or device_id),
                "service_id": service_id,
                "service_name": str(row.get("service_name") or service_id),
                "company": row.get("company"),
                "category": row.get("category"),
                "infrastructure_provider": row.get("infrastructure_provider"),
                "classification_confidence": row.get("classification_confidence"),
                "queries": 0,
                "blocked_queries": 0,
                "domains": Counter(),
                "signal_ids": set(),
                "signal_types": set(),
                "signal_query_counts": Counter(),
                "signal_type_query_counts": Counter(),
            }
            activity[key] = item
        item["first_epoch"] = min(float(item["first_epoch"]), epoch)
        item["last_epoch"] = max(float(item["last_epoch"]), epoch)
        item["queries"] = int(item["queries"]) + 1
        item["blocked_queries"] = int(item["blocked_queries"]) + int(bool(row.get("blocked")))
        domain = str(row.get("domain") or "")
        if domain:
            item["domains"][domain] += 1  # type: ignore[index]
        signal_ids = _split_memberships(row.get("signal_ids"))
        signal_types = _split_memberships(row.get("signal_types"))
        item["signal_ids"].update(signal_ids)  # type: ignore[union-attr]
        item["signal_types"].update(signal_types)  # type: ignore[union-attr]
        item["signal_query_counts"].update(signal_ids)  # type: ignore[union-attr]
        item["signal_type_query_counts"].update(signal_types)  # type: ignore[union-attr]

    activity_rows = [_public_activity(item) for item in activity.values()]
    activity_rows.sort(
        key=lambda item: (
            float(item["bucket_start_epoch"]),
            str(item["device_name"]),
            str(item["service_name"]),
        )
    )
    context = dict(report.get("report_context") or {})
    metadata = {
        "schema_version": LLM_SCHEMA_VERSION,
        "selection": {"scope": scope, "label": label},
        "timezone": context.get("timezone", "Europe/Rome"),
        "report_start_local": context.get("report_start_local"),
        "report_end_local": context.get("report_end_local"),
        "baseline_start_local": context.get("baseline_start_local"),
        "baseline_end_local": context.get("baseline_end_local"),
        "generated_at": report.get("generated_at"),
        "classification_version": context.get("classification_version"),
        "raw_queries_represented": query_count,
        "activity_bucket_seconds": LLM_ACTIVITY_BUCKET_SECONDS,
        "activity_rows": len(activity_rows),
    }

    yield _markdown(
        "# HomeShield DNS report — LLM evidence bundle\n\n"
        "This file is designed for direct analysis by Codex, ChatGPT Work, or another LLM. "
        "Treat every row as DNS name-resolution evidence, not proof that an app was actively used.\n\n"
        "## Analysis contract\n\n"
        "- Prioritize review signals, unknown classifications, and shared infrastructure.\n"
        "- Distinguish allowed queries from blocked queries.\n"
        "- Cite the device, exact local interval, service, and domain when explaining a finding.\n"
        "- Do not infer message contents, searches, page paths, transferred data, or usage duration.\n"
        "- A new or unusual domain is a review lead, not automatically malicious.\n\n"
        "## Machine-readable metadata\n\n```json\n"
        + json.dumps(metadata, ensure_ascii=False, indent=2)
        + "\n```\n\n"
    )

    overview = {
        "scope": report.get("scope"),
        "overview": report.get("overview"),
        "summary": report.get("summary"),
        "caveat": report.get("caveat"),
    }
    yield _markdown(
        "## Scope and overview\n\n```json\n"
        + json.dumps(overview, ensure_ascii=False, indent=2)
        + "\n```\n\n"
    )

    changes = dict(report.get("changes") or {})
    signals = list(changes.get("signals") or [])
    yield _markdown("## Review signals\n\n")
    if signals:
        yield _markdown(
            "Each JSON object is a conservative lead for human/LLM review. Match `signal_id` "
            "or `signal_types` in the activity rows below.\n\n```jsonl\n"
        )
        for signal in signals:
            yield _jsonl_line(signal)
        yield _markdown("```\n\n")
    else:
        yield _markdown("No signal crossed the configured review thresholds.\n\n")

    relevant_service_ids = {str(item["service_id"]) for item in activity_rows}
    services = [
        service
        for service in list(report.get("services") or [])
        if str(service.get("service_id")) in relevant_service_ids
    ]
    yield _markdown(
        "## Services ranked by query volume\n\n"
        "These summaries come from the generated report; use the chronological rows below "
        "for the exact export selection and intervals.\n\n```jsonl\n"
    )
    for service in services:
        yield _jsonl_line(service)
    yield _markdown("```\n\n")

    yield _markdown(
        "## Chronological service activity\n\n"
        "Rows are five-minute buckets grouped by device and classified service. "
        "`first_query_local` and `last_query_local` preserve the exact observed bounds; "
        "`top_domains` is limited to five domains per row. Sections are six-hour analysis chunks.\n\n"
    )
    if not activity_rows:
        yield _markdown("No DNS queries matched this export selection.\n")
        return

    current_chunk: tuple[str, int] | None = None
    for item in activity_rows:
        chunk = _activity_chunk(float(item["bucket_start_epoch"]))
        if chunk != current_chunk:
            if current_chunk is not None:
                yield _markdown("```\n\n")
            current_chunk = chunk
            start_hour = chunk[1]
            end_hour = start_hour + LLM_CHUNK_HOURS - 1
            yield _markdown(
                f"### {chunk[0]} {start_hour:02d}:00–{end_hour:02d}:59 Europe/Rome\n\n```jsonl\n"
            )
        yield _jsonl_line(item)
    yield _markdown("```\n")


def safe_fragment(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:48] or "queries"


def _public_activity(item: Mapping[str, object]) -> dict[str, object]:
    bucket = float(item["bucket_epoch"])
    queries = int(item["queries"])
    blocked = int(item["blocked_queries"])
    domains: Counter[str] = item["domains"]  # type: ignore[assignment]
    return {
        "bucket_start_epoch": int(bucket),
        "bucket_start_local": datetime.fromtimestamp(bucket, ROME).isoformat(timespec="seconds"),
        "first_query_local": datetime.fromtimestamp(float(item["first_epoch"]), ROME).isoformat(timespec="seconds"),
        "last_query_local": datetime.fromtimestamp(float(item["last_epoch"]), ROME).isoformat(timespec="seconds"),
        "device_id": item["device_id"],
        "device_name": item["device_name"],
        "service_id": item["service_id"],
        "service_name": item["service_name"],
        "company": item["company"],
        "category": item["category"],
        "infrastructure_provider": item["infrastructure_provider"],
        "classification_confidence": item["classification_confidence"],
        "queries": queries,
        "allowed_queries": queries - blocked,
        "blocked_queries": blocked,
        "top_domains": [
            {"domain": domain, "queries": count}
            for domain, count in domains.most_common(5)
        ],
        "signal_ids": sorted(item["signal_ids"]),  # type: ignore[arg-type]
        "signal_types": sorted(item["signal_types"]),  # type: ignore[arg-type]
        "signal_query_counts": dict(sorted(item["signal_query_counts"].items())),  # type: ignore[union-attr]
        "signal_type_query_counts": dict(sorted(item["signal_type_query_counts"].items())),  # type: ignore[union-attr]
    }


def _split_memberships(value: object) -> set[str]:
    return {part for part in str(value or "").split(",") if part}


def _activity_chunk(epoch: float) -> tuple[str, int]:
    local = datetime.fromtimestamp(epoch, ROME)
    return local.date().isoformat(), (local.hour // LLM_CHUNK_HOURS) * LLM_CHUNK_HOURS


def _markdown(value: str) -> bytes:
    return value.encode("utf-8")


def _jsonl_line(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def _take(buffer: io.StringIO) -> bytes:
    value = buffer.getvalue().encode("utf-8")
    buffer.seek(0)
    buffer.truncate(0)
    return value


def _spreadsheet_safe(value: object) -> object:
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value
