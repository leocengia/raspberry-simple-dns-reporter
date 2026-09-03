from __future__ import annotations

import time
from collections import Counter, defaultdict
from datetime import datetime
from typing import Iterable

from .classifier import DomainClassifier
from .database import BLOCKED_STATUSES


def build_report(
    rows: Iterable[dict[str, object]],
    device: dict[str, object],
    hours: int,
    classifier: DomainClassifier,
) -> dict[str, object]:
    materialized = list(rows)
    generated_at = time.time()
    bucket_seconds = 1800 if hours == 12 else 3600
    start = generated_at - hours * 3600

    unique_domains: set[str] = set()
    blocked = 0
    overall_buckets: Counter[int] = Counter()
    services: dict[str, dict[str, object]] = {}

    for row in materialized:
        timestamp = float(row["timestamp"])
        status = int(row["status"])
        domain = str(row["domain"] or "").lower().rstrip(".")
        if not domain:
            continue

        unique_domains.add(domain)
        is_blocked = status in BLOCKED_STATUSES
        blocked += int(is_blocked)
        bucket = int(timestamp // bucket_seconds) * bucket_seconds
        overall_buckets[bucket] += 1

        classification = classifier.classify(domain)
        service = services.setdefault(
            classification.service,
            {
                "service": classification.service,
                "company": classification.company,
                "category": classification.category,
                "confidence": classification.confidence,
                "queries": 0,
                "blocked": 0,
                "domains": Counter(),
                "buckets": Counter(),
            },
        )
        service["queries"] = int(service["queries"]) + 1
        service["blocked"] = int(service["blocked"]) + int(is_blocked)
        service["domains"][domain] += 1  # type: ignore[index]
        service["buckets"][bucket] += 1  # type: ignore[index]

    total = len(materialized)
    timeline_buckets = _bucket_range(start, generated_at, bucket_seconds)
    timeline = _timeline(overall_buckets, timeline_buckets)

    service_rows = []
    for service in services.values():
        query_count = int(service["queries"])
        domains: Counter[str] = service.pop("domains")  # type: ignore[assignment]
        buckets: Counter[int] = service.pop("buckets")  # type: ignore[assignment]
        service_rows.append(
            {
                **service,
                "share": round(query_count * 100 / total, 2) if total else 0,
                "timeline": _timeline(buckets, timeline_buckets),
                "domains": [
                    {"domain": domain, "queries": count}
                    for domain, count in domains.most_common(15)
                ],
            }
        )
    service_rows.sort(key=lambda item: int(item["queries"]), reverse=True)

    identified = sum(
        1 for item in service_rows if item["confidence"] != "unknown"
    )
    overview = {
        "total_queries": total,
        "blocked_queries": blocked,
        "blocked_percentage": round(blocked * 100 / total, 2) if total else 0,
        "unique_domains": len(unique_domains),
        "identified_services": identified,
    }

    return {
        "generated_at": datetime.fromtimestamp(generated_at).astimezone().isoformat(),
        "hours": hours,
        "device": {
            key: device.get(key)
            for key in (
                "id",
                "display_name",
                "address",
                "vendor",
                "device_type",
                "present",
                "netalertx_match",
            )
        },
        "overview": overview,
        "timeline": timeline,
        "services": service_rows,
        "summary": _summary(device, overview, service_rows, hours),
        "caveat": (
            "DNS activity shows name-resolution requests, not app usage duration, "
            "content, messages, searches, or transferred data."
        ),
    }


def _bucket_range(start: float, end: float, step: int) -> list[int]:
    first = int(start // step) * step
    last = int(end // step) * step
    return list(range(first, last + step, step))


def _timeline(counts: Counter[int], buckets: list[int]) -> list[dict[str, object]]:
    return [
        {
            "timestamp": datetime.fromtimestamp(bucket).astimezone().isoformat(),
            "label": datetime.fromtimestamp(bucket).strftime("%H:%M"),
            "queries": counts.get(bucket, 0),
        }
        for bucket in buckets
    ]


def _summary(
    device: dict[str, object],
    overview: dict[str, object],
    services: list[dict[str, object]],
    hours: int,
) -> str:
    name = str(device.get("display_name") or "The selected device")
    total = int(overview["total_queries"])
    if not total:
        return f"No DNS activity was recorded for {name} in the last {hours} hours."

    leading = [
        str(service["service"])
        for service in services
        if service["confidence"] != "unknown"
    ][:3]
    service_text = ", ".join(leading) if leading else "unclassified domains"
    return (
        f"In the last {hours} hours, {name} generated {total:,} DNS queries. "
        f"{overview['blocked_percentage']}% were blocked. "
        f"The main identifiable services were {service_text}."
    )
