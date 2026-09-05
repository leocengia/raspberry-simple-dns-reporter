from __future__ import annotations

import json
import logging
import math
import sqlite3
import time
from datetime import datetime, timedelta
from http import HTTPStatus
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Callable, Iterable
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from .classifier import DomainClassifier
from .database import SourceUnavailable, connect_readonly
from .evidence import EvidenceSpec
from .events import ROME, QueryEvent, normalize_event
from .exports import safe_fragment, stream_csv, stream_jsonl, stream_llm_markdown
from .report import build_report
from .settings import Settings
from .snapshots import InvalidSnapshot, SnapshotSigner
from .sources import NetAlertXSource, PiHoleSource


LOGGER = logging.getLogger("dns-reporter")
ALLOWED_HOURS = (3, 6, 12, 24, 48, 168)
WEB_ROOT = Path(__file__).resolve().parent / "web"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class QuietRequestHandler(WSGIRequestHandler):
    server_version = "DNSReporter"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:
        LOGGER.info("request completed")


class Application:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        netalertx = NetAlertXSource(settings.netalertx_db)
        self.pihole = PiHoleSource(
            settings.pihole_db, netalertx, settings.gravity_db
        )
        self.classifier = DomainClassifier.from_file(settings.service_map)
        self.snapshots = SnapshotSigner.ephemeral()

    def __call__(
        self,
        environ: dict[str, object],
        start_response: Callable[..., object],
    ) -> Iterable[bytes]:
        method = str(environ.get("REQUEST_METHOD", "GET")).upper()
        path = str(environ.get("PATH_INFO", "/"))

        try:
            if method == "GET" and path == "/api/health":
                health = self._health()
                status = (
                    HTTPStatus.OK
                    if health["status"] == "ok"
                    else HTTPStatus.SERVICE_UNAVAILABLE
                )
                return self._json(start_response, status, health)
            if method == "GET" and path == "/api/devices":
                devices = self.pihole.list_devices()
                return self._json(
                    start_response,
                    HTTPStatus.OK,
                    {
                        "devices": devices,
                        "groups": self.pihole.list_groups(devices),
                    },
                )
            if method == "POST" and path == "/api/report":
                payload = self._read_json(environ)
                generated_at = time.time()
                window = self._report_window(payload, generated_at)
                hours = window["hours"]
                group = None
                group_identifier = str(payload.get("group_id", ""))
                if group_identifier:
                    group = self.pihole.resolve_group(group_identifier)
                    if group is None:
                        return self._json(
                            start_response,
                            HTTPStatus.NOT_FOUND,
                            {"error": "group not found"},
                        )
                    requested_ids = [str(value) for value in group["device_ids"]]
                else:
                    raw_ids = payload.get("device_ids")
                    if raw_ids is None and payload.get("device_id"):
                        raw_ids = [payload["device_id"]]
                    if not isinstance(raw_ids, list) or not 1 <= len(raw_ids) <= 64:
                        return self._json(
                            start_response,
                            HTTPStatus.BAD_REQUEST,
                            {"error": "select between 1 and 64 devices"},
                        )
                    requested_ids = [str(value) for value in raw_ids]

                devices = self.pihole.resolve_devices(requested_ids)
                if not devices or len(devices) != len(set(requested_ids)):
                    return self._json(
                        start_response,
                        HTTPStatus.NOT_FOUND,
                        {"error": "one or more devices were not found"},
                    )
                addresses = [
                    str(address)
                    for device in devices
                    for address in list(device.get("addresses") or [device["address"]])
                ]
                rows = self.pihole.query_range(
                    addresses,
                    float(window["start"]),
                    float(window["end"]),
                )
                historical = self.pihole.historical_context_range(
                    addresses,
                    float(window["baseline_start"]),
                    float(window["baseline_end"]),
                )
                report = build_report(
                    rows,
                    devices,
                    hours,
                    self.classifier,
                    group=group,
                    generated_at=generated_at,
                    historical=historical,
                    window_start=float(window["start"]),
                    window_end=float(window["end"]),
                    range_kind=str(window["range_kind"]),
                    report_date=window["report_date"],
                    complete_day=window["complete_day"],
                    period_label=window["period_label"],
                )
                self._attach_snapshot(report, devices, addresses)
                return self._json(start_response, HTTPStatus.OK, report)
            if method == "POST" and path == "/api/queries":
                payload = self._read_json(environ)
                snapshot = self._validate_snapshot(str(payload.get("snapshot_token", "")))
                return self._query_page(start_response, payload, snapshot)
            if method == "POST" and path == "/api/exports/queries":
                payload = self._read_json(environ, max_length=131072)
                snapshot = self._validate_snapshot(str(payload.get("snapshot_token", "")))
                return self._export(start_response, payload, snapshot)
            if method == "GET" and path in STATIC_FILES:
                filename, content_type = STATIC_FILES[path]
                return self._file(start_response, filename, content_type)
            return self._json(
                start_response, HTTPStatus.NOT_FOUND, {"error": "not found"}
            )
        except InvalidSnapshot as exc:
            return self._json(
                start_response, HTTPStatus.CONFLICT, {"error": str(exc)}
            )
        except (ValueError, json.JSONDecodeError):
            return self._json(
                start_response, HTTPStatus.BAD_REQUEST, {"error": "invalid request"}
            )
        except SourceUnavailable as exc:
            LOGGER.warning("data source unavailable")
            return self._json(
                start_response,
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": str(exc)},
            )
        except sqlite3.Error as exc:
            LOGGER.warning("data source query failed: %s", exc)
            return self._json(
                start_response,
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "Data source could not complete the request; try again shortly"},
            )
        except Exception:
            LOGGER.exception("request failed")
            return self._json(
                start_response,
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "internal error"},
            )

    def _health(self) -> dict[str, object]:
        sources = {
            "pihole": self._source_readable(self.settings.pihole_db),
            "gravity": self._source_readable(self.settings.gravity_db),
            "netalertx": self._source_readable(self.settings.netalertx_db),
        }
        return {"status": "ok" if all(sources.values()) else "degraded", "sources": sources}

    @staticmethod
    def _source_readable(path: Path) -> bool:
        try:
            with connect_readonly(path) as connection:
                connection.execute("SELECT 1 FROM sqlite_schema LIMIT 1").fetchone()
            return True
        except (SourceUnavailable, sqlite3.Error):
            return False

    @staticmethod
    def _report_window(
        payload: dict[str, object], generated_at: float
    ) -> dict[str, object]:
        requested_date = str(payload.get("report_date", "")).strip()
        if requested_date:
            if "hours" in payload:
                raise ValueError("choose a rolling range or a calendar day")
            try:
                report_day = datetime.strptime(requested_date, "%Y-%m-%d").date()
            except ValueError as exc:
                raise ValueError("invalid report date") from exc
            now_local = datetime.fromtimestamp(generated_at, ROME)
            if report_day > now_local.date():
                raise ValueError("future report date")
            start_local = datetime.combine(report_day, datetime.min.time(), tzinfo=ROME)
            next_local = datetime.combine(
                report_day + timedelta(days=1), datetime.min.time(), tzinfo=ROME
            )
            baseline_local = datetime.combine(
                report_day - timedelta(days=7), datetime.min.time(), tzinfo=ROME
            )
            start = start_local.timestamp()
            next_start = next_local.timestamp()
            complete_day = report_day < now_local.date()
            end = next_start if complete_day else generated_at
            if not start < end <= next_start:
                raise ValueError("invalid report date range")
            duration = (end - start) / 3600
            hours: int | float = int(duration) if duration.is_integer() else round(duration, 6)
            return {
                "start": start,
                "end": end,
                "hours": hours,
                "range_kind": "calendar_day",
                "report_date": requested_date,
                "complete_day": complete_day,
                "period_label": requested_date,
                "baseline_start": baseline_local.timestamp(),
                "baseline_end": start,
            }

        hours = int(payload.get("hours", 24))
        if hours not in ALLOWED_HOURS:
            raise ValueError("unsupported time range")
        start = generated_at - hours * 3600
        return {
            "start": start,
            "end": generated_at,
            "hours": hours,
            "range_kind": "rolling",
            "report_date": None,
            "complete_day": None,
            "period_label": None,
            "baseline_start": start - 7 * 86400,
            "baseline_end": start,
        }

    @staticmethod
    def _read_json(
        environ: dict[str, object], *, max_length: int = 65536
    ) -> dict[str, object]:
        length = int(environ.get("CONTENT_LENGTH") or 0)
        if length < 1 or length > max_length:
            raise ValueError("invalid content length")
        stream = environ["wsgi.input"]
        payload = json.loads(stream.read(length).decode("utf-8"))  # type: ignore[union-attr]
        if not isinstance(payload, dict):
            raise ValueError("JSON object required")
        return payload

    def _attach_snapshot(
        self,
        report: dict[str, object],
        devices: list[dict[str, object]],
        addresses: list[str],
    ) -> None:
        changes = report["changes"]
        services = report["services"]
        signal_snapshots = []
        for signal in changes["signals"]:  # type: ignore[index,union-attr]
            signal_snapshots.append(
                {
                    "signal_id": signal["signal_id"],
                    "kind": signal["kind"],
                    "title": signal["title"],
                    "query_count": signal["query_count"],
                    "evidence": signal.pop("evidence"),
                }
            )
        snapshot = {
            "version": 2,
            "context": report["report_context"],
            "clients": addresses,
            "devices": [
                {
                    "id": device["id"],
                    "display_name": device["display_name"],
                    "identity_confidence": device.get("identity_confidence", "low"),
                    "addresses": list(device.get("addresses") or [device["address"]]),
                }
                for device in devices
            ],
            "signals": signal_snapshots,
            "services": [
                {
                    "service_id": service["service_id"],
                    "service_name": service["service_name"],
                    "query_count": service["queries"],
                }
                for service in services  # type: ignore[union-attr]
            ],
            "llm_report": {
                "generated_at": report["generated_at"],
                "range_kind": report["range_kind"],
                "report_date": report["report_date"],
                "complete_day": report["complete_day"],
                "period_label": report["period_label"],
                "report_context": report["report_context"],
                "scope": report["scope"],
                "overview": report["overview"],
                "summary": report["summary"],
                "caveat": report["caveat"],
                "changes": report["changes"],
                "services": [
                    {
                        key: service.get(key)
                        for key in (
                            "service_id", "service_name", "company", "category",
                            "infrastructure_provider", "confidence", "queries",
                            "blocked", "share", "unique_domains", "domains",
                            "device_breakdown",
                        )
                    }
                    for service in services  # type: ignore[union-attr]
                ],
            },
        }
        report["snapshot_token"] = self.snapshots.sign(snapshot)

    def _validate_snapshot(self, token: str) -> dict[str, object]:
        snapshot = self.snapshots.verify(token)
        context = snapshot.get("context")
        if not isinstance(context, dict):
            raise InvalidSnapshot("invalid report snapshot")
        if context.get("classification_version") != self.classifier.version:
            raise InvalidSnapshot("classification changed; generate a new report")
        start = float(context.get("report_start_epoch", 0))
        end = float(context.get("report_end_epoch", 0))
        if not all(math.isfinite(value) for value in (start, end)) or not start < end:
            raise InvalidSnapshot("invalid report snapshot")
        range_kind = str(context.get("range_kind", "rolling"))
        if range_kind == "rolling":
            hours = int(context.get("hours", 0))
            if hours not in ALLOWED_HOURS or abs((end - start) - hours * 3600) > 1:
                raise InvalidSnapshot("invalid report snapshot")
        elif range_kind == "calendar_day":
            try:
                report_day = datetime.strptime(
                    str(context.get("report_date", "")), "%Y-%m-%d"
                ).date()
                expected_start = datetime.combine(
                    report_day, datetime.min.time(), tzinfo=ROME
                ).timestamp()
                next_start = datetime.combine(
                    report_day + timedelta(days=1), datetime.min.time(), tzinfo=ROME
                ).timestamp()
                generated = float(context["generated_at_epoch"])
            except (KeyError, TypeError, ValueError) as exc:
                raise InvalidSnapshot("invalid report snapshot") from exc
            if (
                not math.isfinite(generated)
                or abs(start - expected_start) > 1
                or not start < end <= next_start
            ):
                raise InvalidSnapshot("invalid report snapshot")
            expected_end = next_start if context.get("complete_day") is True else generated
            if abs(end - expected_end) > 1:
                raise InvalidSnapshot("invalid report snapshot")
        else:
            raise InvalidSnapshot("invalid report snapshot")
        return snapshot

    def _event_iterator(
        self, snapshot: dict[str, object], *, descending: bool
    ) -> Iterable[QueryEvent]:
        context = snapshot["context"]
        devices = snapshot["devices"]
        devices_by_address = {
            str(address): device
            for device in devices  # type: ignore[union-attr]
            for address in device["addresses"]
        }
        rows = self.pihole.query_range(
            [str(client) for client in snapshot["clients"]],  # type: ignore[index]
            float(context["report_start_epoch"]),  # type: ignore[index]
            float(context["report_end_epoch"]),  # type: ignore[index]
            descending=descending,
        )
        for row in rows:  # type: ignore[union-attr]
            event = normalize_event(row, devices_by_address, self.classifier)
            if event is not None:
                yield event

    @staticmethod
    def _selection(
        payload: dict[str, object], snapshot: dict[str, object]
    ) -> tuple[str, object, str]:
        scope = str(payload.get("scope", ""))
        selector = payload.get("selector")
        if not isinstance(selector, dict):
            raise ValueError("selector required")
        if scope == "report":
            llm_report = snapshot.get("llm_report")
            if not isinstance(llm_report, dict):
                raise InvalidSnapshot("report export is unavailable; generate a new report")
            report_scope = llm_report.get("scope")
            if not isinstance(report_scope, dict):
                raise InvalidSnapshot("invalid report snapshot")
            return scope, None, str(report_scope.get("display_name") or "report")
        if scope == "service":
            service_id = str(selector.get("service_id", ""))
            service = next(
                (item for item in snapshot["services"] if item["service_id"] == service_id),  # type: ignore[index]
                None,
            )
            if service is None:
                raise ValueError("unknown service")
            return scope, service_id, str(service["service_name"])
        if scope == "signal":
            identifier = str(selector.get("signal_id", ""))
            signal = next(
                (item for item in snapshot["signals"] if item["signal_id"] == identifier),  # type: ignore[index]
                None,
            )
            if signal is None:
                raise InvalidSnapshot("signal is not part of this report; generate a new report")
            return scope, EvidenceSpec.from_dict(signal["evidence"]), str(signal["title"])
        if scope == "all_signals" and snapshot["signals"]:
            return scope, None, "all"
        raise ValueError("unsupported query scope")

    @staticmethod
    def _memberships(
        event: QueryEvent, snapshot: dict[str, object]
    ) -> list[dict[str, object]]:
        return [
            signal
            for signal in snapshot["signals"]  # type: ignore[index]
            if EvidenceSpec.from_dict(signal["evidence"]).matches(event)
        ]

    def _matching_events(
        self,
        payload: dict[str, object],
        snapshot: dict[str, object],
        *,
        descending: bool,
    ):
        scope, selection, _ = self._selection(payload, snapshot)
        domain_filter = str(payload.get("domain_filter", "")).strip().lower()
        if len(domain_filter) > 200:
            raise ValueError("domain filter too long")
        device_filter = str(payload.get("device_id", ""))
        known_device_ids = {str(item["id"]) for item in snapshot["devices"]}  # type: ignore[index]
        if device_filter and device_filter not in known_device_ids:
            raise ValueError("unknown device")
        for event in self._event_iterator(snapshot, descending=descending):
            memberships = self._memberships(event, snapshot)
            selected = (
                True if scope == "report"
                else event.service_id == selection if scope == "service"
                else bool(memberships) if scope == "all_signals"
                else selection.matches(event)
            )
            if not selected or (domain_filter and domain_filter not in event.domain):
                continue
            if device_filter and event.canonical_device_id != device_filter:
                continue
            yield event, memberships

    def _query_page(
        self,
        start_response: Callable[..., object],
        payload: dict[str, object],
        snapshot: dict[str, object],
    ) -> list[bytes]:
        limit = int(payload.get("limit", 50))
        offset = int(payload.get("offset", 0))
        sort = str(payload.get("sort", "desc"))
        if not 1 <= limit <= 100 or not 0 <= offset <= 1_000_000 or sort not in {"asc", "desc"}:
            raise ValueError("invalid pagination")
        rows: list[dict[str, object]] = []
        total = 0
        context = snapshot["context"]
        unfiltered = not str(payload.get("domain_filter", "")).strip() and not str(payload.get("device_id", ""))
        expected_total = self._expected_count(payload, snapshot) if unfiltered else None
        for event, memberships in self._matching_events(
            payload, snapshot, descending=sort == "desc"
        ):
            if offset <= total < offset + limit:
                row = event.export_dict(
                    context,  # type: ignore[arg-type]
                    [str(item["signal_id"]) for item in memberships],
                    [str(item["kind"]) for item in memberships],
                )
                rows.append(row)
            total += 1
            if expected_total is not None and len(rows) == limit:
                break
        if expected_total is not None:
            total = expected_total
        return self._json(
            start_response, HTTPStatus.OK,
            {"rows": rows, "total": total, "offset": offset, "limit": limit, "has_more": offset + len(rows) < total},
        )

    @staticmethod
    def _expected_count(
        payload: dict[str, object], snapshot: dict[str, object]
    ) -> int | None:
        scope = str(payload.get("scope", ""))
        selector = payload.get("selector")
        if not isinstance(selector, dict):
            return None
        if scope == "service":
            identifier = str(selector.get("service_id", ""))
            item = next((item for item in snapshot["services"] if item["service_id"] == identifier), None)  # type: ignore[index]
            return int(item["query_count"]) if item else None
        if scope == "signal":
            identifier = str(selector.get("signal_id", ""))
            item = next((item for item in snapshot["signals"] if item["signal_id"] == identifier), None)  # type: ignore[index]
            return int(item["query_count"]) if item else None
        return None

    def _export(
        self,
        start_response: Callable[..., object],
        payload: dict[str, object],
        snapshot: dict[str, object],
    ) -> Iterable[bytes]:
        export_format = str(payload.get("format", ""))
        if export_format not in {"csv", "jsonl", "md"}:
            raise ValueError("unsupported export format")
        scope, _, label = self._selection(payload, snapshot)
        context = snapshot["context"]

        def rows():
            for event, memberships in self._matching_events(payload, snapshot, descending=False):
                yield event.export_dict(
                    context,  # type: ignore[arg-type]
                    [str(item["signal_id"]) for item in memberships],
                    [str(item["kind"]) for item in memberships],
                )

        start = datetime.fromtimestamp(float(context["report_start_epoch"]), ROME).strftime("%Y%m%dT%H%M%z")
        end = datetime.fromtimestamp(float(context["report_end_epoch"]), ROME).strftime("%Y%m%dT%H%M%z")
        prefix = (
            "llm-report" if scope == "report"
            else "red-flags" if scope == "all_signals"
            else "red-flag" if scope == "signal"
            else "service"
        )
        filename = f"homeshield_{prefix}_{safe_fragment(label)}_{start}_{end}.{export_format}"
        content_type = (
            "text/csv; charset=utf-8" if export_format == "csv"
            else "application/x-ndjson; charset=utf-8" if export_format == "jsonl"
            else "text/markdown; charset=utf-8"
        )
        headers = self._security_headers(content_type)
        headers.append(("Content-Disposition", f'attachment; filename="{filename}"'))
        start_response("200 OK", headers)
        if export_format == "csv":
            return stream_csv(rows())
        if export_format == "jsonl":
            return stream_jsonl(rows())
        llm_report = snapshot.get("llm_report")
        if not isinstance(llm_report, dict):
            raise InvalidSnapshot("report export is unavailable; generate a new report")
        return stream_llm_markdown(llm_report, rows(), scope=scope, label=label)

    @staticmethod
    def _headers(content_type: str, length: int) -> list[tuple[str, str]]:
        return Application._security_headers(content_type) + [
            ("Content-Length", str(length)),
        ]

    @staticmethod
    def _security_headers(content_type: str) -> list[tuple[str, str]]:
        return [
            ("Content-Type", content_type),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
            (
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
            ),
        ]

    def _json(
        self,
        start_response: Callable[..., object],
        status: HTTPStatus,
        payload: dict[str, object],
    ) -> list[bytes]:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        start_response(
            f"{status.value} {status.phrase}",
            self._headers("application/json; charset=utf-8", len(body)),
        )
        return [body]

    def _file(
        self,
        start_response: Callable[..., object],
        filename: str,
        content_type: str,
    ) -> list[bytes]:
        body = (WEB_ROOT / filename).read_bytes()
        start_response(
            "200 OK", self._headers(content_type, len(body))
        )
        return [body]


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    settings = Settings.from_env()
    application = Application(settings)
    with make_server(
        settings.host,
        settings.port,
        application,
        server_class=ThreadingWSGIServer,
        handler_class=QuietRequestHandler,
    ) as server:
        LOGGER.info("DNS Reporter listening on %s:%s", settings.host, settings.port)
        server.serve_forever()


if __name__ == "__main__":
    main()
