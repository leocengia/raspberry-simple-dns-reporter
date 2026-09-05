from __future__ import annotations

import csv
import io
import json
import re
import sqlite3
import sys
import tempfile
import time
import unittest
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from dns_reporter.classifier import DomainClassifier  # noqa: E402
from dns_reporter.events import ROME, iso_timestamp  # noqa: E402
from dns_reporter.exports import EXPORT_COLUMNS, stream_csv, stream_jsonl  # noqa: E402
from dns_reporter.server import Application  # noqa: E402
from dns_reporter.settings import Settings  # noqa: E402
from dns_reporter.sources import NetAlertXSource, PiHoleSource  # noqa: E402


SERVICE_MAP = PROJECT_ROOT / "src" / "dns_reporter" / "config" / "service_map.json"


class EvidenceTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.pihole_db = root / "pihole.db"
        self.netalertx_db = root / "netalertx.db"
        self.gravity_db = root / "gravity.db"
        self.now = int(time.time())
        with closing(sqlite3.connect(self.pihole_db)) as connection, connection:
            connection.executescript(
                """
                CREATE TABLE queries (
                    id INTEGER PRIMARY KEY, timestamp REAL NOT NULL, type INTEGER,
                    status INTEGER NOT NULL, domain TEXT NOT NULL, client TEXT NOT NULL,
                    forward TEXT, reply_type INTEGER, reply_time REAL, list_id INTEGER
                );
                CREATE TABLE client_by_id (id INTEGER PRIMARY KEY, ip TEXT UNIQUE, name TEXT);
                CREATE TABLE network (id INTEGER PRIMARY KEY, hwaddr TEXT NOT NULL);
                CREATE TABLE network_addresses (network_id INTEGER, ip TEXT, lastSeen INTEGER);
                """
            )
            connection.executemany(
                "INSERT INTO client_by_id(ip,name) VALUES (?,?)",
                [("192.0.2.10", "iPhone.lan"), ("192.0.2.11", "iPhone.lan")],
            )
            connection.executemany(
                "INSERT INTO network(id,hwaddr) VALUES (?,?)",
                [(1, "02:00:00:00:00:10"), (2, "02:00:00:00:00:11")],
            )
            connection.executemany(
                "INSERT INTO network_addresses VALUES (?,?,?)",
                [(1, "192.0.2.10", self.now), (1, "2001:db8::10", self.now), (2, "192.0.2.11", self.now)],
            )
            rows = [
                (self.now - 100, 1, 2, "graph.instagram.com", "192.0.2.10"),
                (self.now - 90, 1, 2, "youtube.com", "2001:db8::10"),
                (self.now - 80, 1, 2, "youtube.com", "192.0.2.11"),
                (self.now - 2 * 86400, 1, 2, "known.example", "192.0.2.10"),
            ]
            connection.executemany(
                "INSERT INTO queries(timestamp,type,status,domain,client) VALUES (?,?,?,?,?)", rows
            )
        with closing(sqlite3.connect(self.netalertx_db)) as connection, connection:
            connection.executescript(
                """
                CREATE TABLE Devices (
                    devMac TEXT, devName TEXT, devVendor TEXT, devType TEXT,
                    devPresentLastScan INTEGER, devLastConnection TEXT, devLastIP TEXT,
                    devPrimaryIPv4 TEXT, devPrimaryIPv6 TEXT, devIsArchived INTEGER
                );
                """
            )
            connection.execute(
                "INSERT INTO Devices VALUES (?,?,?,?,?,?,?,?,?,?)",
                ("02:00:00:00:00:10", "Leonardo phone", "Vendor", "Phone", 1, "", "192.0.2.10", "192.0.2.10", "2001:db8::10", 0),
            )
        with closing(sqlite3.connect(self.gravity_db)) as connection, connection:
            connection.executescript(
                'CREATE TABLE "group" (id INTEGER PRIMARY KEY, enabled INTEGER, name TEXT, description TEXT);'
                "CREATE TABLE client (id INTEGER PRIMARY KEY, ip TEXT);"
                "CREATE TABLE client_by_group (client_id INTEGER, group_id INTEGER);"
            )
        self.settings = Settings("127.0.0.1", 0, self.pihole_db, self.gravity_db, self.netalertx_db, SERVICE_MAP)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_dst_repeated_hour_has_distinct_offsets(self) -> None:
        summer_side = datetime(2026, 10, 25, 0, 30, tzinfo=timezone.utc).timestamp()
        winter_side = datetime(2026, 10, 25, 1, 30, tzinfo=timezone.utc).timestamp()
        self.assertEqual(iso_timestamp(summer_side, ROME), "2026-10-25T02:30:00+02:00")
        self.assertEqual(iso_timestamp(winter_side, ROME), "2026-10-25T02:30:00+01:00")

    def test_calendar_day_reports_follow_rome_dst_boundaries(self) -> None:
        app = Application(self.settings)
        device = self._call_json(app, "GET", "/api/devices")["devices"][0]
        for report_date, expected_hours in (("2025-03-30", 23), ("2025-10-26", 25)):
            report = self._call_json(
                app, "POST", "/api/report",
                {"report_date": report_date, "device_ids": [device["id"]]},
            )
            context = report["report_context"]
            self.assertEqual(report["range_kind"], "calendar_day")
            self.assertEqual(report["report_date"], report_date)
            self.assertTrue(report["complete_day"])
            self.assertEqual(
                context["report_end_epoch"] - context["report_start_epoch"],
                expected_hours * 3600,
            )
            self.assertEqual(app._validate_snapshot(report["snapshot_token"])["context"], context)

    def test_calendar_day_rejects_future_and_ambiguous_ranges(self) -> None:
        app = Application(self.settings)
        device = self._call_json(app, "GET", "/api/devices")["devices"][0]
        status, _, _ = self._call(
            app, "POST", "/api/report",
            {"report_date": "2999-01-01", "device_ids": [device["id"]]},
        )
        self.assertEqual(status, "400 Bad Request")
        status, _, _ = self._call(
            app, "POST", "/api/report",
            {"report_date": "2025-03-30", "hours": 24, "device_ids": [device["id"]]},
        )
        self.assertEqual(status, "400 Bad Request")

    def test_current_calendar_day_ends_at_generation_time(self) -> None:
        generated = datetime(2026, 3, 30, 12, 15, tzinfo=ROME).timestamp()
        window = Application._report_window({"report_date": "2026-03-30"}, generated)
        self.assertFalse(window["complete_day"])
        self.assertEqual(window["end"], generated)
        self.assertEqual(window["baseline_end"], window["start"])

    def test_device_identity_merges_shared_mac_and_disambiguates_names(self) -> None:
        source = PiHoleSource(self.pihole_db, NetAlertXSource(self.netalertx_db))
        devices = source.list_devices(lookback_hours=24)
        self.assertEqual(len(devices), 2)
        merged = next(device for device in devices if len(device["addresses"]) == 2)
        self.assertEqual(merged["query_count"], 2)
        self.assertEqual(merged["identity_confidence"], "high")
        self.assertEqual(len({device["display_name"] for device in devices}), 2)
        self.assertEqual(sum(int(device["query_count"]) for device in devices), 3)

    def test_classifier_separates_specific_and_opaque_akamai(self) -> None:
        classifier = DomainClassifier.from_file(SERVICE_MAP)
        specific = classifier.classify("bag-cdn.itunes-apple.com.akadns.net")
        opaque = classifier.classify("a1744.dscw154.akamai.net")
        self.assertEqual(specific.service_id, "apple-itunes-akamai")
        self.assertEqual(specific.infrastructure_provider, "Akamai")
        self.assertEqual(opaque.service_id, "akamai-infrastructure")
        self.assertEqual(opaque.confidence, "infrastructure/ambiguous")

    def test_query_range_is_half_open_and_preserves_raw_fields(self) -> None:
        source = PiHoleSource(self.pihole_db, NetAlertXSource(self.netalertx_db))
        with closing(sqlite3.connect(self.pihole_db)) as connection, connection:
            connection.execute(
                "INSERT INTO queries(timestamp,type,status,domain,client,reply_type,reply_time,forward,list_id) VALUES (?,?,?,?,?,?,?,?,?)",
                (self.now, 28, 1, "boundary.example", "192.0.2.10", 4, 0.25, "1.1.1.1", 7),
            )
        rows = list(source.query_range(["192.0.2.10"], self.now - 101, self.now))
        self.assertEqual(len(rows), 1)
        self.assertIn("query_id", rows[0])
        self.assertEqual(rows[0]["query_type"], 1)

    def test_service_query_and_streaming_exports_match_report_count(self) -> None:
        app = Application(self.settings)
        devices_payload = self._call_json(app, "GET", "/api/devices")
        merged = next(device for device in devices_payload["devices"] if len(device["addresses"]) == 2)
        report = self._call_json(app, "POST", "/api/report", {"hours": 24, "device_ids": [merged["id"]]})
        youtube = next(service for service in report["services"] if service["service_id"] == "youtube")
        request = {
            "snapshot_token": report["snapshot_token"], "scope": "service",
            "selector": {"service_id": "youtube"}, "limit": 50,
        }
        page = self._call_json(app, "POST", "/api/queries", request)
        self.assertEqual(page["total"], youtube["queries"])
        status, headers, body = self._call(app, "POST", "/api/exports/queries", {**request, "format": "csv"})
        self.assertEqual(status, "200 OK")
        self.assertNotIn("Content-Length", headers)
        self.assertEqual(headers["Cache-Control"], "no-store")
        csv_rows = list(csv.DictReader(io.StringIO(body.decode("utf-8-sig"))))
        self.assertEqual(len(csv_rows), youtube["queries"])
        self.assertEqual(tuple(csv_rows[0]), EXPORT_COLUMNS)
        self.assertEqual(csv_rows[0]["service_id"], "youtube")
        self.assertTrue(csv_rows[0]["timestamp_local"])
        self.assertTrue(csv_rows[0]["timestamp_utc"])

    def test_snapshot_tampering_and_arbitrary_service_are_rejected(self) -> None:
        app = Application(self.settings)
        device = self._call_json(app, "GET", "/api/devices")["devices"][0]
        report = self._call_json(app, "POST", "/api/report", {"hours": 24, "device_ids": [device["id"]]})
        token = report["snapshot_token"]
        status, _, _ = self._call(app, "POST", "/api/queries", {
            "snapshot_token": token[:-1] + ("A" if token[-1] != "A" else "B"),
            "scope": "service", "selector": {"service_id": "youtube"},
        })
        self.assertEqual(status, "409 Conflict")
        status, _, _ = self._call(app, "POST", "/api/queries", {
            "snapshot_token": token, "scope": "service",
            "selector": {"service_id": "anything' OR 1=1 --"},
        })
        self.assertEqual(status, "400 Bad Request")

    def test_serializers_are_valid_utf8_and_formula_safe(self) -> None:
        row = {column: None for column in EXPORT_COLUMNS}
        row.update({"query_id": 7, "device_name": "=unsafe", "domain": "café.example"})
        csv_body = b"".join(stream_csv([row])).decode("utf-8-sig")
        parsed = next(csv.DictReader(io.StringIO(csv_body)))
        self.assertEqual(parsed["device_name"], "'=unsafe")
        self.assertEqual(parsed["domain"], "café.example")
        jsonl_body = b"".join(stream_jsonl([row])).decode("utf-8")
        self.assertEqual(json.loads(jsonl_body)["device_name"], "=unsafe")

    def test_frontend_id_references_exist_in_markup(self) -> None:
        web = PROJECT_ROOT / "src" / "dns_reporter" / "web"
        script = (web / "app.js").read_text(encoding="utf-8")
        markup = (web / "index.html").read_text(encoding="utf-8")
        referenced = set(re.findall(r'querySelector\("#([a-z0-9-]+)"\)', script))
        declared = set(re.findall(r'id="([a-z0-9-]+)"', markup))
        self.assertEqual(referenced - declared, set())

    def test_all_signal_export_deduplicates_overlapping_evidence(self) -> None:
        with closing(sqlite3.connect(self.pihole_db)) as connection, connection:
            connection.executemany(
                "INSERT INTO queries(timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                [(self.now - 200 - offset, 1, 1, "new-unknown.example", "192.0.2.10") for offset in range(100)],
            )
        app = Application(self.settings)
        devices = self._call_json(app, "GET", "/api/devices")["devices"]
        merged = next(device for device in devices if len(device["addresses"]) == 2)
        report = self._call_json(app, "POST", "/api/report", {"hours": 24, "device_ids": [merged["id"]]})
        self.assertGreaterEqual(len(report["changes"]["signals"]), 2)
        request = {
            "snapshot_token": report["snapshot_token"], "format": "jsonl",
            "scope": "all_signals", "selector": {},
        }
        _, headers, body = self._call(app, "POST", "/api/exports/queries", request)
        rows = [json.loads(line) for line in body.splitlines()]
        ids = [row["query_id"] for row in rows]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(any("," in row["signal_ids"] for row in rows))
        for signal in report["changes"]["signals"]:
            page = self._call_json(app, "POST", "/api/queries", {
                "snapshot_token": report["snapshot_token"], "scope": "signal",
                "selector": {"signal_id": signal["signal_id"]}, "limit": 100,
            })
            self.assertEqual(page["total"], signal["query_count"])
        self.assertEqual(headers["Content-Type"], "application/x-ndjson; charset=utf-8")

    def _call_json(self, app: Application, method: str, path: str, payload: dict | None = None) -> dict:
        status, _, body = self._call(app, method, path, payload)
        self.assertTrue(status.startswith("2"), (status, body))
        return json.loads(body)

    @staticmethod
    def _call(app: Application, method: str, path: str, payload: dict | None = None):
        body = json.dumps(payload).encode() if payload is not None else b""
        captured = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        response = app(
            {
                "REQUEST_METHOD": method, "PATH_INFO": path,
                "CONTENT_LENGTH": str(len(body)), "wsgi.input": io.BytesIO(body),
            },
            start_response,
        )
        result = b"".join(response)
        close = getattr(response, "close", None)
        if close:
            close()
        return captured["status"], captured["headers"], result


if __name__ == "__main__":
    unittest.main()
