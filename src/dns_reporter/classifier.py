from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Classification:
    service_id: str
    service: str
    company: str
    category: str
    confidence: str
    infrastructure_provider: str | None
    rule_id: str | None


UNKNOWN = Classification(
    service_id="unknown",
    service="Unknown / Review",
    company="Unknown",
    category="Unknown",
    confidence="unknown",
    infrastructure_provider=None,
    rule_id=None,
)


class DomainClassifier:
    def __init__(self, rules: list[dict[str, object]], version: str) -> None:
        self._rules = rules
        self.version = version

    @classmethod
    def from_file(cls, path: Path) -> "DomainClassifier":
        payload = json.loads(path.read_text(encoding="utf-8"))
        rules = payload.get("rules")
        if not isinstance(rules, list):
            raise ValueError("service map must contain a rules list")
        version = str(payload.get("version", "unknown"))
        return cls(rules, version)

    def classify(self, domain: str) -> Classification:
        normalized = domain.lower().rstrip(".")
        for rule in self._rules:
            suffixes = rule.get("suffixes", [])
            if not isinstance(suffixes, list):
                continue
            if any(
                normalized == suffix or normalized.endswith(f".{suffix}")
                for suffix in suffixes
                if isinstance(suffix, str)
            ):
                return Classification(
                    service_id=str(rule.get("id") or _slug(str(rule["service"]))),
                    service=str(rule["service"]),
                    company=str(rule["company"]),
                    category=str(rule["category"]),
                    confidence=str(rule["confidence"]),
                    infrastructure_provider=(
                        str(rule["infrastructure_provider"])
                        if rule.get("infrastructure_provider")
                        else None
                    ),
                    rule_id=str(rule.get("id") or _slug(str(rule["service"]))),
                )
        return UNKNOWN


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "unknown"
