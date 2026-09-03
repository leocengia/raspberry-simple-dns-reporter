from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Classification:
    service: str
    company: str
    category: str
    confidence: str


UNKNOWN = Classification(
    service="Unknown / Review",
    company="Unknown",
    category="Unknown",
    confidence="unknown",
)


class DomainClassifier:
    def __init__(self, rules: list[dict[str, object]]) -> None:
        self._rules = rules

    @classmethod
    def from_file(cls, path: Path) -> "DomainClassifier":
        payload = json.loads(path.read_text(encoding="utf-8"))
        rules = payload.get("rules")
        if not isinstance(rules, list):
            raise ValueError("service map must contain a rules list")
        return cls(rules)

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
                    service=str(rule["service"]),
                    company=str(rule["company"]),
                    category=str(rule["category"]),
                    confidence=str(rule["confidence"]),
                )
        return UNKNOWN
