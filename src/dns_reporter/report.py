from __future__ import annotations

import time
from collections import Counter, defaultdict
from datetime import datetime
from typing import Iterable

from .classifier import DomainClassifier
from .database import BLOCKED_STATUSES


def build_report(
    rows: Iterable[dict[str, object]],
    devices: dict[str, object] | list[dict[str, object]],
    hours: int,
    classifier: DomainClassifier,
    *,
    group: dict[str, object] | None = None,
    generated_at: float | None = None,
    historical: dict[str, object] | None = None,
) -> dict[str, object]:
    materialized = list(rows)
    selected_devices = [devices] if isinstance(devices, dict) else list(devices)
    if not selected_devices:
        raise ValueError("at least one device is required")
    generated_at = generated_at or time.time()
    if hours <= 12:
        bucket_seconds = 1800
    elif hours <= 48:
        bucket_seconds = 3600
    else:
        bucket_seconds = 21600
    start = generated_at - hours * 3600
    address_to_device = {
        str(device["address"]): device for device in selected_devices
    }

    unique_domains: set[str] = set()
    domain_counts: Counter[str] = Counter()
    domain_first_seen: dict[str, float] = {}
    blocked = 0
    overall_buckets: Counter[int] = Counter()
    hourly_counts: Counter[int] = Counter()
    services: dict[str, dict[str, object]] = {}

    for row in materialized:
        timestamp = float(row["timestamp"])
        status = int(row["status"])
        domain = str(row["domain"] or "").lower().rstrip(".")
        if not domain:
            continue

        unique_domains.add(domain)
        domain_counts[domain] += 1
        domain_first_seen[domain] = min(
            timestamp, domain_first_seen.get(domain, timestamp)
        )
        is_blocked = status in BLOCKED_STATUSES
        blocked += int(is_blocked)
        bucket = int(timestamp // bucket_seconds) * bucket_seconds
        overall_buckets[bucket] += 1
        hourly_counts[int(timestamp // 3600) * 3600] += 1

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
                "devices": Counter(),
            },
        )
        service["queries"] = int(service["queries"]) + 1
        service["blocked"] = int(service["blocked"]) + int(is_blocked)
        service["domains"][domain] += 1  # type: ignore[index]
        service["buckets"][bucket] += 1  # type: ignore[index]
        client = str(row.get("client") or selected_devices[0]["address"])
        selected = address_to_device.get(client)
        if selected is not None:
            service["devices"][str(selected["id"])] += 1  # type: ignore[index]

    total = len(materialized)
    timeline_buckets = _bucket_range(start, generated_at, bucket_seconds)
    timeline = _timeline(overall_buckets, timeline_buckets)

    service_rows = []
    for service in services.values():
        query_count = int(service["queries"])
        domains: Counter[str] = service.pop("domains")  # type: ignore[assignment]
        buckets: Counter[int] = service.pop("buckets")  # type: ignore[assignment]
        device_counts: Counter[str] = service.pop("devices")  # type: ignore[assignment]
        service_rows.append(
            {
                **service,
                "share": round(query_count * 100 / total, 2) if total else 0,
                "timeline": _timeline(buckets, timeline_buckets),
                "domains": [
                    {"domain": domain, "queries": count}
                    for domain, count in domains.most_common(15)
                ],
                "device_breakdown": [
                    {
                        "id": str(device["id"]),
                        "display_name": str(device["display_name"]),
                        "queries": device_counts.get(str(device["id"]), 0),
                    }
                    for device in selected_devices
                ],
            }
        )
    service_rows.sort(key=lambda item: int(item["queries"]), reverse=True)

    identified = sum(
        1 for item in service_rows if item["confidence"] != "unknown"
    )
    changes = _detect_changes(
        domain_counts,
        domain_first_seen,
        hourly_counts,
        service_rows,
        blocked,
        total,
        historical,
        classifier,
    )
    overview = {
        "total_queries": total,
        "blocked_queries": blocked,
        "blocked_percentage": round(blocked * 100 / total, 2) if total else 0,
        "unique_domains": len(unique_domains),
        "identified_services": identified,
        "selected_devices": len(selected_devices),
        "new_domains": changes["new_domain_count"],
        "new_services": changes["new_service_count"],
    }

    public_devices = [
        {
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
        }
        for device in selected_devices
    ]
    if group is not None:
        scope_type = "group"
        scope_id = str(group["id"])
        scope_name = str(group["display_name"])
    elif len(selected_devices) == 1:
        scope_type = "device"
        scope_id = str(selected_devices[0]["id"])
        scope_name = str(selected_devices[0]["display_name"])
    else:
        scope_type = "devices"
        scope_id = "multiple"
        scope_name = f"{len(selected_devices)} selected devices"

    scope = {
        "type": scope_type,
        "id": scope_id,
        "display_name": scope_name,
        "device_count": len(selected_devices),
        "devices": public_devices,
    }

    return {
        "generated_at": datetime.fromtimestamp(generated_at).astimezone().isoformat(),
        "hours": hours,
        "scope": scope,
        "device": public_devices[0] if len(public_devices) == 1 else None,
        "overview": overview,
        "timeline": timeline,
        "services": service_rows,
        "changes": changes,
        "summary": _summary(scope, overview, service_rows, hours, changes),
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
    scope: dict[str, object],
    overview: dict[str, object],
    services: list[dict[str, object]],
    hours: int,
    changes: dict[str, object],
) -> str:
    name = str(scope.get("display_name") or "The selected devices")
    total = int(overview["total_queries"])
    period = "7 days" if hours == 168 else f"{hours} hours"
    if not total:
        return f"No DNS activity was recorded for {name} in the last {period}."

    leading = [
        service
        for service in services
        if service["confidence"] != "unknown"
    ][:3]
    service_text = (
        ", ".join(str(service["service"]) for service in leading)
        if leading
        else "unclassified domains"
    )
    base = (
        f"In the last {period}, {name} generated {total:,} DNS queries. "
        f"{overview['blocked_percentage']}% were blocked. "
        f"The main identifiable services were {service_text}."
    )
    if leading:
        primary = leading[0]
        peak = max(
            primary["timeline"],
            key=lambda point: int(point["queries"]),
            default=None,
        )
        if peak and int(peak["queries"]):
            base += (
                f" {primary['service']} had its highest DNS-request bucket around "
                f"{peak['label']} ({int(peak['queries']):,} queries)."
            )
    if changes["baseline_days"]:
        new_domain_count = int(overview["new_domains"])
        noun = "domain" if new_domain_count == 1 else "domains"
        verb = "was" if new_domain_count == 1 else "were"
        base += (
            f" {new_domain_count:,} {noun} {verb} not observed in the "
            f"preceding {changes['baseline_days']} days."
        )
    signal_count = len(changes["signals"])  # type: ignore[arg-type]
    if signal_count:
        return (
            f"{base} {signal_count} signal{'s' if signal_count != 1 else ''} "
            "were highlighted for review; none is automatically classified as malicious."
        )
    if not changes["baseline_days"]:
        return f"{base} Historical comparison was unavailable."
    return f"{base} No notable changes crossed the review thresholds."


def _detect_changes(
    current_domains: Counter[str],
    domain_first_seen: dict[str, float],
    current_hours: Counter[int],
    services: list[dict[str, object]],
    blocked: int,
    total: int,
    historical: dict[str, object] | None,
    classifier: DomainClassifier,
) -> dict[str, object]:
    if not historical:
        return {
            "baseline_days": 0,
            "new_domain_count": 0,
            "new_service_count": 0,
            "signals": [],
        }

    baseline_days = int(historical.get("baseline_days", 7))
    historical_domains = set(
        str(domain) for domain in dict(historical.get("domain_counts", {}))
    )
    new_domains = current_domains.keys() - historical_domains
    historical_services = {
        classifier.classify(domain).service for domain in historical_domains
    }
    current_services = {
        str(service["service"])
        for service in services
        if service["confidence"] != "unknown"
    }
    new_services = sorted(current_services - historical_services)
    signals: list[dict[str, object]] = []

    high_volume_threshold = max(20, int(total * 0.01))
    high_volume_new = [
        {
            "domain": domain,
            "queries": count,
            "first_seen": datetime.fromtimestamp(
                domain_first_seen[domain]
            ).astimezone().isoformat(),
        }
        for domain, count in current_domains.most_common()
        if domain in new_domains and count >= high_volume_threshold
    ][:10]
    if high_volume_new:
        signals.append(
            {
                "kind": "new_domains",
                "severity": "review",
                "title": "New high-volume domains",
                "detail": (
                    f"{len(high_volume_new)} domain(s) were not observed in the "
                    f"previous {baseline_days} days and generated at least "
                    f"{high_volume_threshold:,} queries in this report."
                ),
                "domains": high_volume_new,
            }
        )

    if new_services:
        signals.append(
            {
                "kind": "new_services",
                "severity": "notice",
                "title": "Services new to the baseline",
                "detail": (
                    f"{len(new_services)} identified service(s) were not seen in "
                    f"the previous {baseline_days} days."
                ),
                "services": new_services[:10],
            }
        )

    historical_by_clock_hour: defaultdict[int, list[int]] = defaultdict(list)
    for point in list(historical.get("hour_counts", [])):
        timestamp = float(point["timestamp"])
        historical_by_clock_hour[datetime.fromtimestamp(timestamp).hour].append(
            int(point["queries"])
        )
    spikes: list[tuple[float, int, int, float]] = []
    for timestamp, count in current_hours.items():
        hour = datetime.fromtimestamp(timestamp).hour
        samples = historical_by_clock_hour.get(hour, [])
        if not samples:
            continue
        average = sum(samples) / len(samples)
        ratio = count / max(average, 1)
        if count >= 100 and count - average >= 50 and ratio >= 4:
            spikes.append((ratio, timestamp, count, average))
    if spikes:
        ratio, timestamp, count, average = max(spikes)
        label = datetime.fromtimestamp(timestamp).strftime("%H:00–%H:59")
        signals.append(
            {
                "kind": "activity_spike",
                "severity": "review",
                "title": "Unusual DNS activity spike",
                "detail": (
                    f"{count:,} queries occurred around {label}, about {ratio:.1f}× "
                    f"the {baseline_days}-day average of {average:.0f} for that hour."
                ),
            }
        )

    blocked_percentage = blocked * 100 / total if total else 0
    if total >= 100 and blocked_percentage >= 50:
        leading_blocked = max(
            services, key=lambda service: int(service["blocked"]), default=None
        )
        blocked_context = ""
        if leading_blocked and int(leading_blocked["blocked"]):
            blocked_context = (
                f" The largest classified contributor was "
                f"{leading_blocked['service']} ({leading_blocked['category']})."
            )
        signals.append(
            {
                "kind": "blocked_share",
                "severity": "notice",
                "title": "High blocked-query share",
                "detail": (
                    f"Pi-hole blocked {blocked_percentage:.1f}% of queries in this "
                    "report. This can be normal for telemetry-heavy devices."
                    f"{blocked_context}"
                ),
            }
        )

    unknown = next(
        (service for service in services if service["confidence"] == "unknown"),
        None,
    )
    if unknown and int(unknown["queries"]) >= 50 and float(unknown["share"]) >= 20:
        signals.append(
            {
                "kind": "unknown_activity",
                "severity": "notice",
                "title": "Large unclassified share",
                "detail": (
                    f"{unknown['share']}% of queries could not be mapped confidently "
                    "to a service and may merit classification review."
                ),
                "domains": list(unknown["domains"])[:5],
            }
        )

    return {
        "baseline_days": baseline_days,
        "baseline_start": datetime.fromtimestamp(float(historical["start"])).astimezone().isoformat(),
        "baseline_end": datetime.fromtimestamp(float(historical["end"])).astimezone().isoformat(),
        "new_domain_count": len(new_domains),
        "new_service_count": len(new_services),
        "signals": signals,
    }
