from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Mapping
from zoneinfo import ZoneInfo

from .classifier import DomainClassifier
from .database import BLOCKED_STATUSES


APP_TIMEZONE = "Europe/Rome"
ROME = ZoneInfo(APP_TIMEZONE)


@dataclass(frozen=True)
class QueryEvent:
    query_id: int
    timestamp_epoch: int | float
    timestamp_utc: str
    timestamp_local: str
    timezone: str
    client_key: str
    client_ip: str | None
    canonical_device_id: str
    device_name: str
    device_identity_confidence: str
    domain: str
    service_id: str
    service_name: str
    company: str | None
    category: str
    infrastructure_provider: str | None
    classification_confidence: str
    classification_rule_id: str | None
    classification_version: str
    query_type_raw: int | None
    query_type_label: str | None
    status_raw: int
    status_label: str
    blocked: bool
    reply_type_raw: int | None
    reply_type_label: str | None
    reply_time: float | None
    forward: str | None
    list_id: int | None

    def export_dict(
        self,
        context: Mapping[str, object],
        signal_ids: list[str] | None = None,
        signal_types: list[str] | None = None,
    ) -> dict[str, object]:
        result = asdict(self)
        result.update(
            {
                "signal_ids": ",".join(signal_ids or []),
                "signal_types": ",".join(signal_types or []),
                "report_start_local": context["report_start_local"],
                "report_end_local": context["report_end_local"],
                "baseline_start_local": context.get("baseline_start_local"),
                "baseline_end_local": context.get("baseline_end_local"),
            }
        )
        return result


def iso_timestamp(epoch: float, zone: ZoneInfo | timezone) -> str:
    value = datetime.fromtimestamp(epoch, zone)
    rendered = value.isoformat(timespec="seconds")
    return rendered.replace("+00:00", "Z") if zone is timezone.utc else rendered


def display_timestamp(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, ROME).strftime("%Y-%m-%d %H:%M:%S %Z")


def normalize_event(
    row: Mapping[str, object],
    devices_by_address: Mapping[str, Mapping[str, object]],
    classifier: DomainClassifier,
) -> QueryEvent | None:
    domain = str(row.get("domain") or "").lower().rstrip(".")
    if not domain:
        return None
    epoch_value = float(row["timestamp"])
    epoch: int | float = int(epoch_value) if epoch_value.is_integer() else epoch_value
    client = str(row.get("client") or "")
    device = devices_by_address.get(client, {})
    classification = classifier.classify(domain)
    status = int(row.get("status") or 0)
    blocked = status in BLOCKED_STATUSES
    return QueryEvent(
        query_id=int(row.get("query_id") or 0),
        timestamp_epoch=epoch,
        timestamp_utc=iso_timestamp(epoch_value, timezone.utc),
        timestamp_local=iso_timestamp(epoch_value, ROME),
        timezone=APP_TIMEZONE,
        client_key=client,
        client_ip=client or None,
        canonical_device_id=str(device.get("id") or "unknown"),
        device_name=str(device.get("display_name") or client or "Unknown client"),
        device_identity_confidence=str(device.get("identity_confidence") or "low"),
        domain=domain,
        service_id=classification.service_id,
        service_name=classification.service,
        company=None if classification.company == "Unknown" else classification.company,
        category=classification.category,
        infrastructure_provider=classification.infrastructure_provider,
        classification_confidence=classification.confidence,
        classification_rule_id=classification.rule_id,
        classification_version=classifier.version,
        query_type_raw=_optional_int(row.get("query_type")),
        query_type_label=None,
        status_raw=status,
        status_label="blocked" if blocked else "allowed",
        blocked=blocked,
        reply_type_raw=_optional_int(row.get("reply_type")),
        reply_type_label=None,
        reply_time=_optional_float(row.get("reply_time")),
        forward=str(row["forward"]) if row.get("forward") is not None else None,
        list_id=_optional_int(row.get("list_id")),
    )


def _optional_int(value: object) -> int | None:
    return int(value) if value is not None else None


def _optional_float(value: object) -> float | None:
    return float(value) if value is not None else None
