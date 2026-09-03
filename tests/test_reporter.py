from __future__ import annotations

import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from dns_reporter.classifier import DomainClassifier  # noqa: E402
from dns_reporter.database import BLOCKED_STATUSES, connect_readonly  # noqa: E402
from dns_reporter.report import build_report  # noqa: E402
from dns_reporter.sources import (  # noqa: E402
    NetAlertXSource,
    PiHoleSource,
    device_id,
)


SERVICE_MAP = PROJECT_ROOT / "src" / "dns_reporter" / "config" / "service_map.json"


class ReporterTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.pihole_db = root / "pihole.db"
        self.netalertx_db = root / "netalertx.db"
        self.gravity_db = root / "gravity.db"
        self._create_pihole_fixture()
        self._create_netalertx_fixture()
        self._create_gravity_fixture()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _create_pihole_fixture(self) -> None:
        now = time.time()
        with sqlite3.connect(self.pihole_db) as connection:
            connection.executescript(
                """
                CREATE TABLE queries (
                    timestamp REAL NOT NULL,
                    status INTEGER NOT NULL,
                    domain TEXT NOT NULL,
                    client TEXT NOT NULL
                );
                CREATE TABLE client_by_id (
                    id INTEGER PRIMARY KEY,
                    ip TEXT UNIQUE NOT NULL,
                    name TEXT
                );
                CREATE TABLE network (
                    id INTEGER PRIMARY KEY,
                    hwaddr TEXT NOT NULL
                );
                CREATE TABLE network_addresses (
                    network_id INTEGER NOT NULL,
                    ip TEXT NOT NULL
                );
                """
            )
            connection.execute(
                "INSERT INTO client_by_id(ip, name) VALUES (?, ?)",
                ("192.0.2.10", ""),
            )
            connection.executemany(
                "INSERT INTO queries(timestamp, status, domain, client) VALUES (?, ?, ?, ?)",
                [
                    (now - 100, 2, "graph.instagram.com", "192.0.2.10"),
                    (now - 90, 1, "gateway.facebook.com", "192.0.2.10"),
                    (now - 80, 16, "mask.icloud.com", "192.0.2.10"),
                    (now - 70, 17, "example.invalid", "192.0.2.10"),
                    (now - 60, 2, "youtube.com", "192.0.2.20"),
                    (now - 2 * 86400, 2, "known.example", "192.0.2.10"),
                ],
            )
            connection.execute(
                "INSERT INTO client_by_id(ip, name) VALUES (?, ?)",
                ("192.0.2.20", "Test laptop"),
            )
            connection.execute(
                "INSERT INTO network(id, hwaddr) VALUES (?, ?)",
                (1, "02:00:00:00:00:10"),
            )
            connection.execute(
                "INSERT INTO network_addresses(network_id, ip) VALUES (?, ?)",
                (1, "192.0.2.10"),
            )

    def _create_netalertx_fixture(self) -> None:
        with sqlite3.connect(self.netalertx_db) as connection:
            connection.executescript(
                """
                CREATE TABLE Devices (
                    devName TEXT,
                    devVendor TEXT,
                    devType TEXT,
                    devPresentLastScan INTEGER,
                    devLastConnection TEXT,
                    devLastIP TEXT,
                    devPrimaryIPv4 TEXT,
                    devPrimaryIPv6 TEXT,
                    devIsArchived INTEGER
                );
                """
            )
            connection.execute(
                "INSERT INTO Devices VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "Test phone",
                    "Example vendor",
                    "Phone",
                    1,
                    "2033-05-18 03:31:00",
                    "192.0.2.10",
                    "",
                    "",
                    0,
                ),
            )

    def _create_gravity_fixture(self) -> None:
        with sqlite3.connect(self.gravity_db) as connection:
            connection.executescript(
                """
                CREATE TABLE "group" (
                    id INTEGER PRIMARY KEY,
                    enabled INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT
                );
                CREATE TABLE client (
                    id INTEGER PRIMARY KEY,
                    ip TEXT NOT NULL
                );
                CREATE TABLE client_by_group (
                    client_id INTEGER NOT NULL,
                    group_id INTEGER NOT NULL
                );
                INSERT INTO "group" VALUES (1, 1, 'Personal devices', 'Fixture group');
                INSERT INTO client VALUES (1, '192.0.2.0/24');
                INSERT INTO client_by_group VALUES (1, 1);
                """
            )

    def test_readonly_connection_rejects_writes(self) -> None:
        with connect_readonly(self.pihole_db) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queries").fetchone()[0], 6)
            with self.assertRaises(sqlite3.OperationalError):
                connection.execute("DELETE FROM queries")

    def test_classifier_prefers_specific_service(self) -> None:
        classifier = DomainClassifier.from_file(SERVICE_MAP)
        result = classifier.classify("r1---sn.googlevideo.com")
        self.assertEqual(result.service, "YouTube")
        self.assertEqual(result.confidence, "high")

    def test_blocked_status_set_matches_supported_statuses(self) -> None:
        self.assertIn(1, BLOCKED_STATUSES)
        self.assertIn(16, BLOCKED_STATUSES)
        self.assertNotIn(2, BLOCKED_STATUSES)
        self.assertNotIn(17, BLOCKED_STATUSES)

    def test_netalertx_enriches_device_without_exposing_config(self) -> None:
        source = PiHoleSource(self.pihole_db, NetAlertXSource(self.netalertx_db))
        devices = source.list_devices(lookback_hours=1_000_000)
        phone = next(device for device in devices if device["address"] == "192.0.2.10")
        self.assertEqual(phone["display_name"], "Test phone")
        self.assertEqual(phone["vendor"], "Example vendor")
        self.assertTrue(phone["netalertx_match"])
        self.assertEqual(phone["id"], device_id("192.0.2.10"))

    def test_pihole_groups_resolve_to_recent_devices(self) -> None:
        source = PiHoleSource(
            self.pihole_db,
            NetAlertXSource(self.netalertx_db),
            self.gravity_db,
        )
        groups = source.list_groups(source.list_devices(lookback_hours=1_000_000))
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["display_name"], "Personal devices")
        self.assertEqual(groups[0]["device_count"], 2)

    def test_historical_context_is_aggregated(self) -> None:
        source = PiHoleSource(self.pihole_db, NetAlertXSource(self.netalertx_db))
        historical = source.historical_context(
            ["192.0.2.10"], 24, time.time(), baseline_days=7
        )
        self.assertEqual(historical["domain_counts"], {"known.example": 1})
        self.assertEqual(len(historical["hour_counts"]), 1)

    def test_report_metrics_and_service_drilldown(self) -> None:
        classifier = DomainClassifier.from_file(SERVICE_MAP)
        rows = [
            {"timestamp": 2_000_000_000.0, "status": 2, "domain": "graph.instagram.com"},
            {"timestamp": 2_000_000_010.0, "status": 1, "domain": "gateway.facebook.com"},
            {"timestamp": 2_000_000_020.0, "status": 16, "domain": "mask.icloud.com"},
            {"timestamp": 2_000_000_030.0, "status": 17, "domain": "example.invalid"},
        ]
        device = {
            "id": "test",
            "display_name": "Test phone",
            "address": "192.0.2.10",
            "vendor": "Example vendor",
            "device_type": "Phone",
            "present": True,
            "netalertx_match": True,
        }
        report = build_report(rows, device, 24, classifier)
        self.assertEqual(report["overview"]["total_queries"], 4)
        self.assertEqual(report["overview"]["blocked_queries"], 2)
        self.assertEqual(report["overview"]["blocked_percentage"], 50.0)
        self.assertEqual(report["overview"]["unique_domains"], 4)
        meta = next(item for item in report["services"] if item["service"] == "Meta / Instagram")
        self.assertEqual(meta["queries"], 2)
        self.assertEqual(meta["blocked"], 1)
        self.assertEqual(len(meta["domains"]), 2)

    def test_multi_device_report_has_comparison(self) -> None:
        classifier = DomainClassifier.from_file(SERVICE_MAP)
        devices = [
            {"id": "phone", "display_name": "Phone", "address": "192.0.2.10"},
            {"id": "laptop", "display_name": "Laptop", "address": "192.0.2.20"},
        ]
        rows = [
            {"timestamp": time.time(), "status": 2, "domain": "youtube.com", "client": "192.0.2.10"},
            {"timestamp": time.time(), "status": 2, "domain": "youtube.com", "client": "192.0.2.20"},
            {"timestamp": time.time(), "status": 2, "domain": "youtube.com", "client": "192.0.2.20"},
        ]
        report = build_report(rows, devices, 24, classifier)
        self.assertEqual(report["scope"]["device_count"], 2)
        youtube = next(item for item in report["services"] if item["service"] == "YouTube")
        counts = {item["id"]: item["queries"] for item in youtube["device_breakdown"]}
        self.assertEqual(counts, {"phone": 1, "laptop": 2})

    def test_changes_flag_new_high_volume_domains(self) -> None:
        now = time.time()
        classifier = DomainClassifier.from_file(SERVICE_MAP)
        rows = [
            {
                "timestamp": now - offset,
                "status": 2,
                "domain": "new.example",
                "client": "192.0.2.10",
            }
            for offset in range(25)
        ]
        rows.append(
            {
                "timestamp": now - 30,
                "status": 2,
                "domain": "youtube.com",
                "client": "192.0.2.10",
            }
        )
        historical = {
            "baseline_days": 7,
            "start": now - 8 * 86400,
            "end": now - 86400,
            "domain_counts": {"youtube.com": 10},
            "hour_counts": [],
        }
        report = build_report(
            rows,
            {"id": "phone", "display_name": "Phone", "address": "192.0.2.10"},
            24,
            classifier,
            generated_at=now,
            historical=historical,
        )
        self.assertEqual(report["overview"]["new_domains"], 1)
        self.assertIn(
            "new_domains",
            {signal["kind"] for signal in report["changes"]["signals"]},
        )


if __name__ == "__main__":
    unittest.main()
