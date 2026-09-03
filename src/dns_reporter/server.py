from __future__ import annotations

import json
import logging
import os
import time
from http import HTTPStatus
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Callable, Iterable
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from .classifier import DomainClassifier
from .database import SourceUnavailable
from .report import build_report
from .settings import Settings
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
                hours = int(payload.get("hours", 24))
                if hours not in ALLOWED_HOURS:
                    return self._json(
                        start_response,
                        HTTPStatus.BAD_REQUEST,
                        {"error": "unsupported time range"},
                    )
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
                generated_at = time.time()
                addresses = [str(device["address"]) for device in devices]
                rows = self.pihole.query_rows(
                    addresses,
                    hours,
                    generated_at,
                )
                historical = self.pihole.historical_context(
                    addresses,
                    hours,
                    generated_at,
                )
                report = build_report(
                    rows,
                    devices,
                    hours,
                    self.classifier,
                    group=group,
                    generated_at=generated_at,
                    historical=historical,
                )
                return self._json(start_response, HTTPStatus.OK, report)
            if method == "GET" and path in STATIC_FILES:
                filename, content_type = STATIC_FILES[path]
                return self._file(start_response, filename, content_type)
            return self._json(
                start_response, HTTPStatus.NOT_FOUND, {"error": "not found"}
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
        except Exception:
            LOGGER.exception("request failed")
            return self._json(
                start_response,
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "internal error"},
            )

    def _health(self) -> dict[str, object]:
        sources = {
            "pihole": os.access(self.settings.pihole_db, os.R_OK),
            "gravity": os.access(self.settings.gravity_db, os.R_OK),
            "netalertx": os.access(self.settings.netalertx_db, os.R_OK),
        }
        return {"status": "ok" if all(sources.values()) else "degraded", "sources": sources}

    @staticmethod
    def _read_json(environ: dict[str, object]) -> dict[str, object]:
        length = int(environ.get("CONTENT_LENGTH") or 0)
        if length < 1 or length > 4096:
            raise ValueError("invalid content length")
        stream = environ["wsgi.input"]
        payload = json.loads(stream.read(length).decode("utf-8"))  # type: ignore[union-attr]
        if not isinstance(payload, dict):
            raise ValueError("JSON object required")
        return payload

    @staticmethod
    def _headers(content_type: str, length: int) -> list[tuple[str, str]]:
        return [
            ("Content-Type", content_type),
            ("Content-Length", str(length)),
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
