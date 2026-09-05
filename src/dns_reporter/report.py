from __future__ import annotations

import hashlib
import json
import time
from collections import Counter, defaultdict
from datetime import datetime
from typing import Iterable

from .classifier import DomainClassifier
from .evidence import EvidenceSpec, signal_id
from .events import APP_TIMEZONE, ROME, iso_timestamp, normalize_event


def build_report(
    rows: Iterable[dict[str, object]],
    devices: dict[str, object] | list[dict[str, object]],
    hours: int | float,
    classifier: DomainClassifier,
    *,
    group: dict[str, object] | None = None,
    generated_at: float | None = None,
    historical: dict[str, object] | None = None,
    window_start: float | None = None,
    window_end: float | None = None,
    range_kind: str = "rolling",
    report_date: str | None = None,
    complete_day: bool | None = None,
    period_label: str | None = None,
) -> dict[str, object]:
    selected_devices = [devices] if isinstance(devices, dict) else list(devices)
    if not selected_devices:
        raise ValueError("at least one device is required")
    generated = float(generated_at or time.time())
    end = float(window_end if window_end is not None else generated)
    start = float(window_start if window_start is not None else end - hours * 3600)
    duration_hours = (end - start) / 3600
    bucket_seconds = 1800 if duration_hours <= 12 else 3600 if duration_hours <= 48 else 21600
    devices_by_address = {
        str(address): device
        for device in selected_devices
        for address in list(device.get("addresses") or [device["address"]])
    }
    domain_counts: Counter[str] = Counter()
    domain_first_seen: dict[str, float] = {}
    domain_devices: defaultdict[str, set[str]] = defaultdict(set)
    overall_buckets: Counter[int] = Counter()
    hourly_counts: Counter[int] = Counter()
    hourly_domains: defaultdict[int, set[str]] = defaultdict(set)
    hourly_devices: defaultdict[int, set[str]] = defaultdict(set)
    services: dict[str, dict[str, object]] = {}
    blocked = 0
    blocked_domains: set[str] = set()
    blocked_devices: set[str] = set()
    total = 0
    for row in rows:
        event = normalize_event(row, devices_by_address, classifier)
        if event is None:
            continue
        total += 1
        timestamp = float(event.timestamp_epoch)
        domain_counts[event.domain] += 1
        domain_devices[event.domain].add(event.canonical_device_id)
        domain_first_seen[event.domain] = min(timestamp, domain_first_seen.get(event.domain, timestamp))
        blocked += int(event.blocked)
        if event.blocked:
            blocked_domains.add(event.domain)
            blocked_devices.add(event.canonical_device_id)
        bucket = int(timestamp // bucket_seconds) * bucket_seconds
        overall_buckets[bucket] += 1
        hour_bucket = int(timestamp // 3600) * 3600
        hourly_counts[hour_bucket] += 1
        hourly_domains[hour_bucket].add(event.domain)
        hourly_devices[hour_bucket].add(event.canonical_device_id)
        service = services.setdefault(
            event.service_id,
            {
                "service_id": event.service_id,
                "service": event.service_name,
                "service_name": event.service_name,
                "company": event.company or "Unknown",
                "category": event.category,
                "infrastructure_provider": event.infrastructure_provider,
                "confidence": event.classification_confidence,
                "classification_rule_id": event.classification_rule_id,
                "queries": 0,
                "blocked": 0,
                "domains": Counter(),
                "buckets": Counter(),
                "devices": Counter(),
            },
        )
        service["queries"] = int(service["queries"]) + 1
        service["blocked"] = int(service["blocked"]) + int(event.blocked)
        service["domains"][event.domain] += 1  # type: ignore[index]
        service["buckets"][bucket] += 1  # type: ignore[index]
        service["devices"][event.canonical_device_id] += 1  # type: ignore[index]

    timeline_buckets = _bucket_range(start, end, bucket_seconds)
    service_rows: list[dict[str, object]] = []
    for service in services.values():
        query_count = int(service["queries"])
        domains: Counter[str] = service.pop("domains")  # type: ignore[assignment]
        buckets: Counter[int] = service.pop("buckets")  # type: ignore[assignment]
        device_counts: Counter[str] = service.pop("devices")  # type: ignore[assignment]
        top_domains = domains.most_common(15)
        service_rows.append(
            {
                **service,
                "share": round(query_count * 100 / total, 2) if total else 0,
                "timeline": _timeline(buckets, timeline_buckets),
                "unique_domains": len(domains),
                "domains_truncated": len(domains) > len(top_domains),
                "domains": [{"domain": domain, "queries": count} for domain, count in top_domains],
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

    public_devices = [
        {key: device.get(key) for key in (
            "id", "display_name", "address", "vendor", "device_type", "present",
            "netalertx_match", "identity_confidence",
        )}
        for device in selected_devices
    ]
    scope = _scope(public_devices, group)
    baseline_start = float(historical["start"]) if historical else None
    baseline_end = float(historical["end"]) if historical else None
    context = {
        "report_start_epoch": start,
        "report_end_epoch": end,
        "report_start_local": iso_timestamp(start, ROME),
        "report_end_local": iso_timestamp(end, ROME),
        "baseline_start_epoch": baseline_start,
        "baseline_end_epoch": baseline_end,
        "baseline_start_local": iso_timestamp(baseline_start, ROME) if baseline_start is not None else None,
        "baseline_end_local": iso_timestamp(baseline_end, ROME) if baseline_end is not None else None,
        "timezone": APP_TIMEZONE,
        "device_ids": [str(device["id"]) for device in selected_devices],
        "classification_version": classifier.version,
        "hours": hours,
        "range_kind": range_kind,
        "report_date": report_date,
        "complete_day": complete_day,
        "generated_at_epoch": generated,
    }
    changes = _detect_changes(
        total, domain_counts, domain_first_seen, domain_devices, hourly_counts,
        hourly_domains, hourly_devices, service_rows, blocked, blocked_domains,
        blocked_devices, historical, classifier, context,
    )
    overview = {
        "total_queries": total,
        "blocked_queries": blocked,
        "blocked_percentage": round(blocked * 100 / total, 2) if total else 0,
        "unique_domains": len(domain_counts),
        "identified_services": sum(1 for item in service_rows if item["confidence"] != "unknown"),
        "selected_devices": len(selected_devices),
        "new_domains": changes["new_domain_count"],
        "new_services": changes["new_service_count"],
    }
    return {
        "generated_at": iso_timestamp(generated, ROME),
        "hours": hours,
        "range_kind": range_kind,
        "report_date": report_date,
        "complete_day": complete_day,
        "period_label": period_label,
        "timezone": APP_TIMEZONE,
        "report_context": context,
        "scope": scope,
        "device": public_devices[0] if len(public_devices) == 1 else None,
        "overview": overview,
        "timeline": _timeline(overall_buckets, timeline_buckets),
        "services": service_rows,
        "changes": changes,
        "summary": _summary(
            scope, overview, service_rows, hours, changes,
            range_kind=range_kind, period_label=period_label,
        ),
        "caveat": (
            "DNS activity shows name-resolution requests, not app usage duration, "
            "content, messages, searches, or transferred data."
        ),
    }


def _scope(public_devices: list[dict[str, object]], group: dict[str, object] | None) -> dict[str, object]:
    if group is not None:
        scope_type, scope_id, scope_name = "group", str(group["id"]), str(group["display_name"])
    elif len(public_devices) == 1:
        scope_type, scope_id = "device", str(public_devices[0]["id"])
        scope_name = str(public_devices[0]["display_name"])
    else:
        scope_type, scope_id = "devices", "multiple"
        scope_name = f"{len(public_devices)} selected devices"
    return {
        "type": scope_type, "id": scope_id, "display_name": scope_name,
        "device_count": len(public_devices), "devices": public_devices,
    }


def _bucket_range(start: float, end: float, step: int) -> list[int]:
    first = int(start // step) * step
    # `end` is exclusive throughout the query API.  Do not add an empty bucket
    # whose start is exactly the end of an aligned report window.
    stop = int((end + step - 1) // step) * step
    return list(range(first, stop, step))


def _timeline(counts: Counter[int], buckets: list[int]) -> list[dict[str, object]]:
    return [
        {
            "timestamp": iso_timestamp(bucket, ROME),
            "label": datetime.fromtimestamp(bucket, ROME).strftime("%H:%M"),
            "queries": counts.get(bucket, 0),
        }
        for bucket in buckets
    ]


def _context_key(context: dict[str, object]) -> str:
    safe = {
        "start": context["report_start_epoch"], "end": context["report_end_epoch"],
        "devices": context["device_ids"], "classifier": context["classification_version"],
    }
    return hashlib.sha256(json.dumps(safe, sort_keys=True).encode()).hexdigest()[:20]


def _make_signal(
    *, kind: str, severity: str, title: str, detail: str,
    spec: EvidenceSpec, metrics: dict[str, int], context: dict[str, object], **extra: object,
) -> dict[str, object]:
    return {
        "signal_id": signal_id(kind, spec, _context_key(context)),
        "kind": kind, "severity": severity, "title": title, "detail": detail,
        **metrics,
        "interval": {
            **spec.public_interval(),
            "start_local": iso_timestamp(spec.start_epoch, ROME),
            "end_local": iso_timestamp(spec.end_epoch, ROME),
        },
        "evidence": spec.to_dict(),
        **extra,
    }


def _detect_changes(
    total: int, current_domains: Counter[str], domain_first_seen: dict[str, float],
    domain_devices: dict[str, set[str]], current_hours: Counter[int],
    hourly_domains: dict[int, set[str]], hourly_devices: dict[int, set[str]],
    services: list[dict[str, object]], blocked: int, blocked_domains: set[str],
    blocked_devices: set[str],
    historical: dict[str, object] | None, classifier: DomainClassifier,
    context: dict[str, object],
) -> dict[str, object]:
    if not historical:
        return {"baseline_days": 0, "new_domain_count": 0, "new_service_count": 0, "signals": []}
    baseline_days = int(historical.get("baseline_days", 7))
    historical_domains = {str(domain) for domain in dict(historical.get("domain_counts", {}))}
    new_domains = current_domains.keys() - historical_domains
    historical_service_ids = {classifier.classify(domain).service_id for domain in historical_domains}
    current_services = {
        str(service["service_id"]): str(service["service"])
        for service in services if service["confidence"] != "unknown"
    }
    new_service_ids = sorted(set(current_services) - historical_service_ids)
    report_start = float(context["report_start_epoch"])
    report_end = float(context["report_end_epoch"])
    signals: list[dict[str, object]] = []

    threshold = max(20, int(total * 0.01))
    high_volume_new = [
        {"domain": domain, "queries": count, "first_seen": iso_timestamp(domain_first_seen[domain], ROME)}
        for domain, count in current_domains.most_common()
        if domain in new_domains and count >= threshold
    ][:10]
    if high_volume_new:
        spec = EvidenceSpec(
            "new_domains", report_start, report_end,
            domains=tuple(str(item["domain"]) for item in high_volume_new),
        )
        signals.append(_make_signal(
            kind="new_domains", severity="review", title="New high-volume domains",
            detail=(f"{len(high_volume_new)} domain(s) were not observed in the previous "
                    f"{baseline_days} days and generated at least {threshold:,} queries in this report."),
            spec=spec,
            metrics={
                "query_count": sum(current_domains[str(item["domain"])] for item in high_volume_new),
                "device_count": len(set().union(*(domain_devices[str(item["domain"])] for item in high_volume_new))),
                "unique_domains": len(high_volume_new),
            },
            context=context, domains=high_volume_new,
        ))

    if new_service_ids:
        spec = EvidenceSpec("new_services", report_start, report_end, service_ids=tuple(new_service_ids))
        signals.append(_make_signal(
            kind="new_services", severity="notice", title="Services new to the baseline",
            detail=f"{len(new_service_ids)} identified service(s) were not seen in the previous {baseline_days} days.",
            spec=spec,
            metrics={
                "query_count": sum(int(service["queries"]) for service in services if service["service_id"] in new_service_ids),
                "device_count": len({
                    str(device["id"])
                    for service in services if service["service_id"] in new_service_ids
                    for device in service["device_breakdown"] if int(device["queries"])
                }),
                "unique_domains": sum(int(service["unique_domains"]) for service in services if service["service_id"] in new_service_ids),
            },
            context=context,
            services=[current_services[item] for item in new_service_ids[:10]],
        ))

    historical_by_clock_hour: defaultdict[int, list[int]] = defaultdict(list)
    for point in list(historical.get("hour_counts", [])):
        timestamp = float(point["timestamp"])
        historical_by_clock_hour[datetime.fromtimestamp(timestamp, ROME).hour].append(int(point["queries"]))
    spikes: list[tuple[float, int, int, float]] = []
    for timestamp, count in current_hours.items():
        samples = historical_by_clock_hour.get(datetime.fromtimestamp(timestamp, ROME).hour, [])
        if not samples:
            continue
        average = sum(samples) / len(samples)
        ratio = count / max(average, 1)
        if count >= 100 and count - average >= 50 and ratio >= 4:
            spikes.append((ratio, timestamp, count, average))
    if spikes:
        ratio, timestamp, count, average = max(spikes)
        start, end = max(report_start, float(timestamp)), min(report_end, float(timestamp + 3600))
        label = datetime.fromtimestamp(timestamp, ROME).strftime("%H:00–%H:59")
        signals.append(_make_signal(
            kind="activity_spike", severity="review", title="Unusual DNS activity spike",
            detail=(f"{count:,} queries occurred around {label}, about {ratio:.1f}× the "
                    f"{baseline_days}-day average of {average:.0f} for that hour."),
            spec=EvidenceSpec("activity_spike", start, end),
            metrics={
                "query_count": count,
                "device_count": len(hourly_devices[timestamp]),
                "unique_domains": len(hourly_domains[timestamp]),
            },
            context=context,
        ))

    blocked_percentage = blocked * 100 / total if total else 0
    if total >= 100 and blocked_percentage >= 50:
        leading = max(services, key=lambda service: int(service["blocked"]), default=None)
        contributor = (
            f" The largest classified contributor was {leading['service']} ({leading['category']})."
            if leading and int(leading["blocked"]) else ""
        )
        signals.append(_make_signal(
            kind="blocked_share", severity="notice", title="High blocked-query share",
            detail=(f"Pi-hole blocked {blocked_percentage:.1f}% of queries in this report. "
                    f"This can be normal for telemetry-heavy devices.{contributor}"),
            spec=EvidenceSpec("blocked_share", report_start, report_end, blocked_only=True),
            metrics={
                "query_count": blocked,
                "device_count": len(blocked_devices),
                "unique_domains": len(blocked_domains),
            },
            context=context,
        ))

    unknown = next((service for service in services if service["confidence"] == "unknown"), None)
    if unknown and int(unknown["queries"]) >= 50 and float(unknown["share"]) >= 20:
        signals.append(_make_signal(
            kind="unknown_activity", severity="notice", title="Large unclassified share",
            detail=(f"{unknown['share']}% of queries could not be mapped confidently to a service "
                    "and may merit classification review."),
            spec=EvidenceSpec("unknown_activity", report_start, report_end, confidence="unknown"),
            metrics={
                "query_count": int(unknown["queries"]),
                "device_count": sum(1 for device in unknown["device_breakdown"] if int(device["queries"])),
                "unique_domains": int(unknown["unique_domains"]),
            },
            context=context, domains=list(unknown["domains"])[:5],
        ))
    return {
        "baseline_days": baseline_days,
        "baseline_start": iso_timestamp(float(historical["start"]), ROME),
        "baseline_end": iso_timestamp(float(historical["end"]), ROME),
        "new_domain_count": len(new_domains),
        "new_service_count": len(new_service_ids),
        "signals": signals,
    }


def _summary(
    scope: dict[str, object], overview: dict[str, object], services: list[dict[str, object]],
    hours: int | float, changes: dict[str, object], *, range_kind: str = "rolling",
    period_label: str | None = None,
) -> str:
    name = str(scope.get("display_name") or "The selected devices")
    total = int(overview["total_queries"])
    period = "7 days" if hours == 168 else f"{hours} hours"
    prefix = f"On {period_label}" if range_kind == "calendar_day" else f"In the last {period}"
    if not total:
        return f"No DNS activity was recorded for {name} {prefix.lower()}."
    leading = [service for service in services if service["confidence"] != "unknown"][:3]
    service_text = ", ".join(str(service["service"]) for service in leading) if leading else "unclassified domains"
    base = (f"{prefix}, {name} generated {total:,} DNS queries. "
            f"{overview['blocked_percentage']}% were blocked. The main identifiable services were {service_text}.")
    if changes["baseline_days"]:
        count = int(overview["new_domains"])
        base += f" {count:,} {'domain' if count == 1 else 'domains'} {'was' if count == 1 else 'were'} not observed in the preceding {changes['baseline_days']} days."
    signal_count = len(changes["signals"])  # type: ignore[arg-type]
    if signal_count:
        return f"{base} {signal_count} signal{'s' if signal_count != 1 else ''} were highlighted for review; none is automatically classified as malicious."
    if not changes["baseline_days"]:
        return f"{base} Historical comparison was unavailable."
    return f"{base} No notable changes crossed the review thresholds."
