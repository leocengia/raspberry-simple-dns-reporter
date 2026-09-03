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
    def __init__(self, database_path: Path, netalertx: NetAlertXSource) -> None:
        self.database_path = database_path
        self.netalertx = netalertx

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

    def query_rows(self, client: str, hours: int) -> list[dict[str, object]]:
        cutoff = time.time() - hours * 3600
        with connect_readonly(self.database_path) as connection:
            rows = connection.execute(
                """
                SELECT timestamp, status, domain
                FROM queries
                WHERE timestamp >= ? AND client = ?
                ORDER BY timestamp
                """,
                (cutoff, client),
            ).fetchall()
        return [dict(row) for row in rows]


def device_id(address: str) -> str:
    return hashlib.sha256(address.encode("utf-8")).hexdigest()[:16]


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
