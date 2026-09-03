from __future__ import annotations

import hashlib
import ipaddress
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from .database import SourceUnavailable, connect_readonly


UNKNOWN_NAMES = {"", "(unknown)", "unknown", "none", "null"}


@dataclass(frozen=True)
class NetAlertDevice:
    name: str
    vendor: str
    device_type: str
    present: bool
    last_connection: str
    addresses: frozenset[str]


class NetAlertXSource:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def devices_by_address(self) -> dict[str, NetAlertDevice]:
        with connect_readonly(self.database_path) as connection:
            rows = connection.execute(
                """
                SELECT devName, devVendor, devType, devPresentLastScan,
                       devLastConnection, devLastIP, devPrimaryIPv4,
                       devPrimaryIPv6
                FROM Devices
                WHERE COALESCE(devIsArchived, 0) = 0
                """
            ).fetchall()

        result: dict[str, NetAlertDevice] = {}
        for row in rows:
            addresses = _extract_addresses(
                row["devLastIP"], row["devPrimaryIPv4"], row["devPrimaryIPv6"]
            )
            device = NetAlertDevice(
                name=_clean_name(row["devName"]),
                vendor=(row["devVendor"] or "").strip(),
                device_type=(row["devType"] or "").strip(),
                present=bool(row["devPresentLastScan"]),
                last_connection=str(row["devLastConnection"] or ""),
                addresses=frozenset(addresses),
            )
            for address in addresses:
                result[address] = device
        return result


class PiHoleSource:
    def __init__(
        self,
        database_path: Path,
        netalertx: NetAlertXSource,
        gravity_database_path: Path | None = None,
    ) -> None:
        self.database_path = database_path
        self.netalertx = netalertx
        self.gravity_database_path = gravity_database_path

    def list_devices(self, lookback_hours: int = 168) -> list[dict[str, object]]:
        cutoff = time.time() - lookback_hours * 3600
        with connect_readonly(self.database_path) as connection:
            rows = connection.execute(
                """
                SELECT q.client,
                       COALESCE(MAX(c.name), '') AS pihole_name,
                       COUNT(*) AS query_count,
                       MAX(q.timestamp) AS last_seen
                FROM queries AS q
                LEFT JOIN client_by_id AS c ON c.ip = q.client
                WHERE q.timestamp >= ?
                GROUP BY q.client
                ORDER BY last_seen DESC
                """,
                (cutoff,),
            ).fetchall()

        try:
            netalert_devices = self.netalertx.devices_by_address()
            netalert_available = True
        except (SourceUnavailable, sqlite3.Error):
            netalert_devices = {}
            netalert_available = False

        devices: list[dict[str, object]] = []
        for row in rows:
            address = str(row["client"])
            netalert = netalert_devices.get(_normalize_address(address))
            pihole_name = _clean_name(row["pihole_name"])
            display_name = pihole_name or (netalert.name if netalert else "") or address
            devices.append(
                {
                    "id": device_id(address),
                    "display_name": display_name,
                    "address": address,
                    "query_count": int(row["query_count"]),
                    "last_seen": float(row["last_seen"]),
                    "vendor": netalert.vendor if netalert else "",
                    "device_type": netalert.device_type if netalert else "",
                    "present": netalert.present if netalert else None,
                    "netalertx_match": bool(netalert),
                    "netalertx_available": netalert_available,
                }
            )
        return devices

    def resolve_device(self, opaque_id: str) -> dict[str, object] | None:
        for device in self.list_devices():
            if device["id"] == opaque_id:
                return device
        return None

    def resolve_devices(self, opaque_ids: list[str]) -> list[dict[str, object]]:
        requested = set(opaque_ids)
        return [device for device in self.list_devices() if device["id"] in requested]

    def list_groups(
        self, devices: list[dict[str, object]] | None = None
    ) -> list[dict[str, object]]:
        if self.gravity_database_path is None:
            return []

        devices = devices if devices is not None else self.list_devices()
        hardware_by_address = self._hardware_by_address()
        try:
            with connect_readonly(self.gravity_database_path) as connection:
                rows = connection.execute(
                    """
                    SELECT g.id, g.name, COALESCE(g.description, '') AS description,
                           c.ip AS selector
                    FROM "group" AS g
                    LEFT JOIN client_by_group AS cbg ON cbg.group_id = g.id
                    LEFT JOIN client AS c ON c.id = cbg.client_id
                    WHERE g.enabled = 1
                    ORDER BY LOWER(g.name), c.ip
                    """
                ).fetchall()
        except (SourceUnavailable, sqlite3.Error):
            return []

        grouped: dict[int, dict[str, object]] = {}
        for row in rows:
            numeric_id = int(row["id"])
            group = grouped.setdefault(
                numeric_id,
                {
                    "id": group_id(numeric_id),
                    "display_name": str(row["name"]),
                    "description": str(row["description"]),
                    "selectors": [],
                },
            )
            if row["selector"]:
                group["selectors"].append(str(row["selector"]))  # type: ignore[union-attr]

        result: list[dict[str, object]] = []
        for group in grouped.values():
            selectors = list(group.pop("selectors"))
            member_ids = [
                str(device["id"])
                for device in devices
                if any(
                    _selector_matches(
                        selector,
                        str(device["address"]),
                        hardware_by_address.get(
                            _normalize_address(str(device["address"])), ""
                        ),
                    )
                    for selector in selectors
                )
            ]
            result.append(
                {
                    **group,
                    "device_ids": member_ids,
                    "device_count": len(member_ids),
                }
            )
        return result

    def resolve_group(self, opaque_id: str) -> dict[str, object] | None:
        for group in self.list_groups():
            if group["id"] == opaque_id:
                return group
        return None

    def query_rows(
        self,
        clients: list[str],
        hours: int,
        end_time: float | None = None,
    ) -> list[dict[str, object]]:
        unique_clients = list(dict.fromkeys(clients))
        if not unique_clients or len(unique_clients) > 64:
            raise ValueError("between 1 and 64 clients are required")
        end = end_time or time.time()
        cutoff = end - hours * 3600
        placeholders = ",".join("?" for _ in unique_clients)
        with connect_readonly(self.database_path) as connection:
            rows = connection.execute(
                f"""
                SELECT timestamp, status, domain, client
                FROM queries
                WHERE timestamp >= ? AND timestamp <= ?
                  AND client IN ({placeholders})
                ORDER BY timestamp
                """,
                (cutoff, end, *unique_clients),
            ).fetchall()
        return [dict(row) for row in rows]

    def historical_context(
        self,
        clients: list[str],
        hours: int,
        end_time: float,
        baseline_days: int = 7,
    ) -> dict[str, object]:
        unique_clients = list(dict.fromkeys(clients))
        if not unique_clients or len(unique_clients) > 64:
            raise ValueError("between 1 and 64 clients are required")
        current_start = end_time - hours * 3600
        baseline_start = current_start - baseline_days * 86400
        placeholders = ",".join("?" for _ in unique_clients)
        parameters = (baseline_start, current_start, *unique_clients)
        with connect_readonly(self.database_path) as connection:
            domain_rows = connection.execute(
                f"""
                SELECT domain, COUNT(*) AS query_count
                FROM queries
                WHERE timestamp >= ? AND timestamp < ?
                  AND client IN ({placeholders})
                GROUP BY domain
                """,
                parameters,
            ).fetchall()
            hour_rows = connection.execute(
                f"""
                SELECT CAST(timestamp / 3600 AS INTEGER) AS hour_bucket,
                       COUNT(*) AS query_count
                FROM queries
                WHERE timestamp >= ? AND timestamp < ?
                  AND client IN ({placeholders})
                GROUP BY hour_bucket
                ORDER BY hour_bucket
                """,
                parameters,
            ).fetchall()
        return {
            "baseline_days": baseline_days,
            "start": baseline_start,
            "end": current_start,
            "domain_counts": {
                str(row["domain"] or "").lower().rstrip("."): int(row["query_count"])
                for row in domain_rows
                if row["domain"]
            },
            "hour_counts": [
                {
                    "timestamp": int(row["hour_bucket"]) * 3600,
                    "queries": int(row["query_count"]),
                }
                for row in hour_rows
            ],
        }

    def _hardware_by_address(self) -> dict[str, str]:
        try:
            with connect_readonly(self.database_path) as connection:
                rows = connection.execute(
                    """
                    SELECT a.ip, n.hwaddr
                    FROM network_addresses AS a
                    JOIN network AS n ON n.id = a.network_id
                    """
                ).fetchall()
        except (SourceUnavailable, sqlite3.Error):
            return {}
        return {
            _normalize_address(str(row["ip"])): str(row["hwaddr"] or "").lower()
            for row in rows
        }


def device_id(address: str) -> str:
    return hashlib.sha256(address.encode("utf-8")).hexdigest()[:16]


def group_id(numeric_id: int) -> str:
    return hashlib.sha256(f"group:{numeric_id}".encode("utf-8")).hexdigest()[:16]


def _clean_name(value: object) -> str:
    name = str(value or "").strip()
    return "" if name.lower() in UNKNOWN_NAMES else name


def _normalize_address(value: str) -> str:
    candidate = value.strip().strip("[]")
    if "%" in candidate:
        candidate = candidate.split("%", 1)[0]
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        return candidate.lower()


def _extract_addresses(*values: object) -> set[str]:
    addresses: set[str] = set()
    for value in values:
        if not value:
            continue
        for candidate in re.split(r"[\s,;|\[\]\"']+", str(value)):
            candidate = candidate.strip()
            if not candidate:
                continue
            normalized = _normalize_address(candidate)
            try:
                ipaddress.ip_address(normalized)
            except ValueError:
                continue
            addresses.add(normalized)
    return addresses


def _selector_matches(selector: str, address: str, hardware_address: str) -> bool:
    candidate = selector.strip().lower()
    normalized_address = _normalize_address(address)
    if candidate == hardware_address.lower() and hardware_address:
        return True
    try:
        if "/" in candidate:
            return ipaddress.ip_address(normalized_address) in ipaddress.ip_network(
                candidate, strict=False
            )
        return ipaddress.ip_address(candidate) == ipaddress.ip_address(normalized_address)
    except ValueError:
        return candidate == normalized_address.lower()
