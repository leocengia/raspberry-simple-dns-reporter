from __future__ import annotations

import hashlib
import ipaddress
import re
import sqlite3
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .database import SourceUnavailable, connect_readonly


UNKNOWN_NAMES = {"", "(unknown)", "unknown", "none", "null"}


@dataclass(frozen=True)
class NetAlertDevice:
    stable_key: str | None
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
            columns = {
                str(row["name"]) for row in connection.execute("PRAGMA table_info(Devices)")
            }
            mac_expression = "devMac" if "devMac" in columns else "NULL"
            rows = connection.execute(
                f"""
                SELECT {mac_expression} AS stable_mac,
                       devName, devVendor, devType, devPresentLastScan,
                       devLastConnection, devLastIP, devPrimaryIPv4,
                       devPrimaryIPv6
                FROM Devices
                WHERE COALESCE(devIsArchived, 0) = 0
                """
            ).fetchall()

        result: dict[str, NetAlertDevice] = {}
        ambiguous_addresses: set[str] = set()
        for row in rows:
            addresses = _extract_addresses(
                row["devLastIP"], row["devPrimaryIPv4"], row["devPrimaryIPv6"]
            )
            device = NetAlertDevice(
                stable_key=_stable_hardware_key(row["stable_mac"]),
                name=_clean_name(row["devName"]),
                vendor=(row["devVendor"] or "").strip(),
                device_type=(row["devType"] or "").strip(),
                present=bool(row["devPresentLastScan"]),
                last_connection=str(row["devLastConnection"] or ""),
                addresses=frozenset(addresses),
            )
            for address in addresses:
                if address in ambiguous_addresses:
                    continue
                existing = result.get(address)
                if existing is not None and existing != device:
                    result.pop(address, None)
                    ambiguous_addresses.add(address)
                else:
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

        hardware_by_address = self._hardware_by_address()
        grouped: dict[str, dict[str, object]] = {}
        for row in rows:
            address = str(row["client"])
            normalized = _normalize_address(address)
            netalert = netalert_devices.get(normalized)
            pihole_name = _clean_name(row["pihole_name"])
            display_name = pihole_name or (netalert.name if netalert else "") or address
            hardware_key = _stable_hardware_key(hardware_by_address.get(normalized))
            stable_key = (netalert.stable_key if netalert else None) or hardware_key
            canonical_key = f"hardware:{stable_key}" if stable_key else f"client:{normalized}"
            item = grouped.setdefault(
                canonical_key,
                {
                    "id": device_id(canonical_key),
                    "display_name": display_name,
                    "address": address,
                    "addresses": [],
                    "query_count": 0,
                    "last_seen": 0.0,
                    "vendor": netalert.vendor if netalert else "",
                    "device_type": netalert.device_type if netalert else "",
                    "present": netalert.present if netalert else None,
                    "netalertx_match": bool(netalert),
                    "netalertx_available": netalert_available,
                    "identity_confidence": "high" if stable_key else "low",
                },
            )
            item["addresses"].append(address)  # type: ignore[union-attr]
            item["query_count"] = int(item["query_count"]) + int(row["query_count"])
            if float(row["last_seen"]) >= float(item["last_seen"]):
                item["last_seen"] = float(row["last_seen"])
                item["address"] = address
                if pihole_name or not item["display_name"]:
                    item["display_name"] = display_name

        devices = sorted(grouped.values(), key=lambda item: float(item["last_seen"]), reverse=True)
        duplicate_names: dict[str, int] = {}
        for device in devices:
            key = str(device["display_name"]).casefold()
            duplicate_names[key] = duplicate_names.get(key, 0) + 1
        for device in devices:
            if duplicate_names[str(device["display_name"]).casefold()] > 1:
                device["display_name"] = f"{device['display_name']} · {str(device['id'])[-4:].upper()}"
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
                        address,
                        hardware_by_address.get(
                            _normalize_address(address), ""
                        ),
                    )
                    for selector in selectors
                    for address in list(device.get("addresses") or [device["address"]])
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
        end = end_time or time.time()
        return list(self.query_range(clients, end - hours * 3600, end))

    def query_range(
        self,
        clients: list[str],
        start_time: float,
        end_time: float,
        *,
        descending: bool = False,
        chunk_size: int = 1000,
    ) -> Iterator[dict[str, object]]:
        unique_clients = list(dict.fromkeys(clients))
        if not unique_clients or len(unique_clients) > 128:
            raise ValueError("between 1 and 128 clients are required")
        if not start_time < end_time:
            raise ValueError("invalid time range")
        return self._query_range_iterator(
            unique_clients, start_time, end_time, descending, chunk_size
        )

    def _query_range_iterator(
        self,
        clients: list[str],
        start_time: float,
        end_time: float,
        descending: bool,
        chunk_size: int,
    ) -> Iterator[dict[str, object]]:
        placeholders = ",".join("?" for _ in clients)
        direction = "DESC" if descending else "ASC"
        with connect_readonly(self.database_path) as connection:
            columns = {
                str(row["name"]) for row in connection.execute("PRAGMA table_info(queries)")
            }
            optional = {
                "query_id": "id" if "id" in columns else "rowid",
                "query_type": "type" if "type" in columns else "NULL",
                "reply_type": "reply_type" if "reply_type" in columns else "NULL",
                "reply_time": "reply_time" if "reply_time" in columns else "NULL",
                "forward": "forward" if "forward" in columns else "NULL",
                "list_id": "list_id" if "list_id" in columns else "NULL",
            }
            cursor = connection.execute(
                f"""
                SELECT {optional['query_id']} AS query_id,
                       timestamp, {optional['query_type']} AS query_type,
                       status, domain, client,
                       {optional['reply_type']} AS reply_type,
                       {optional['reply_time']} AS reply_time,
                       {optional['forward']} AS forward,
                       {optional['list_id']} AS list_id
                FROM queries
                WHERE timestamp >= ? AND timestamp < ?
                  AND client IN ({placeholders})
                ORDER BY timestamp {direction}, query_id {direction}
                """,
                (start_time, end_time, *clients),
            )
            while rows := cursor.fetchmany(chunk_size):
                for row in rows:
                    yield dict(row)

    def historical_context(
        self,
        clients: list[str],
        hours: int,
        end_time: float,
        baseline_days: int = 7,
    ) -> dict[str, object]:
        unique_clients = list(dict.fromkeys(clients))
        if not unique_clients or len(unique_clients) > 128:
            raise ValueError("between 1 and 128 clients are required")
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
                address_columns = {
                    str(row["name"])
                    for row in connection.execute("PRAGMA table_info(network_addresses)")
                }
                recency_order = (
                    "lastSeen DESC, network_id DESC"
                    if "lastSeen" in address_columns
                    else "network_id DESC"
                )
                rows = connection.execute(
                    f"""
                    SELECT recent.ip, n.hwaddr
                    FROM (
                        SELECT ip, network_id,
                               ROW_NUMBER() OVER (
                                   PARTITION BY ip
                                   ORDER BY {recency_order}
                               ) AS position
                        FROM network_addresses
                    ) AS recent
                    JOIN network AS n ON n.id = recent.network_id
                    WHERE recent.position = 1
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


def _stable_hardware_key(value: object) -> str | None:
    candidate = str(value or "").strip().lower().replace("-", ":")
    if not candidate or candidate in {"00:00:00:00:00:00", "(unknown)"}:
        return None
    if re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", candidate):
        return candidate
    if re.fullmatch(r"[0-9a-f]{12}", candidate):
        return ":".join(candidate[index:index + 2] for index in range(0, 12, 2))
    return None


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
