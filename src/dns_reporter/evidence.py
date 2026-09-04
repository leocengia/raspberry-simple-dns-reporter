from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from .events import QueryEvent


@dataclass(frozen=True)
class EvidenceSpec:
    kind: str
    start_epoch: float
    end_epoch: float
    domains: tuple[str, ...] = ()
    service_ids: tuple[str, ...] = ()
    blocked_only: bool = False
    confidence: str | None = None

    def matches(self, event: QueryEvent) -> bool:
        if not self.start_epoch <= float(event.timestamp_epoch) < self.end_epoch:
            return False
        if self.domains and event.domain not in self.domains:
            return False
        if self.service_ids and event.service_id not in self.service_ids:
            return False
        if self.blocked_only and not event.blocked:
            return False
        if self.confidence and event.classification_confidence != self.confidence:
            return False
        return True

    def public_interval(self) -> dict[str, float]:
        return {"start_epoch": self.start_epoch, "end_epoch": self.end_epoch}

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> "EvidenceSpec":
        return cls(
            kind=str(value["kind"]),
            start_epoch=float(value["start_epoch"]),
            end_epoch=float(value["end_epoch"]),
            domains=tuple(str(item) for item in value.get("domains", [])),
            service_ids=tuple(str(item) for item in value.get("service_ids", [])),
            blocked_only=bool(value.get("blocked_only", False)),
            confidence=(str(value["confidence"]) if value.get("confidence") else None),
        )


def signal_id(kind: str, spec: EvidenceSpec, context_key: str) -> str:
    serialized = json.dumps(
        {"kind": kind, "spec": spec.to_dict(), "context": context_key},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(serialized).hexdigest()[:20]
    return f"{kind}:{digest}"
