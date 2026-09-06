from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass


class InvalidSnapshot(ValueError):
    pass


@dataclass
class SnapshotSigner:
    secret: bytes
    max_age_seconds: int = 86400

    @classmethod
    def ephemeral(cls) -> "SnapshotSigner":
        return cls(secrets.token_bytes(32))

    def sign(self, payload: dict[str, object]) -> str:
        body = json.dumps(
            {**payload, "issued_at": int(time.time())},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        encoded = _encode(body)
        signature = _encode(hmac.new(self.secret, encoded.encode("ascii"), hashlib.sha256).digest())
        return f"{encoded}.{signature}"

    def verify(self, token: str) -> dict[str, object]:
        try:
            encoded, supplied = token.split(".", 1)
            expected = _encode(
                hmac.new(self.secret, encoded.encode("ascii"), hashlib.sha256).digest()
            )
            if not hmac.compare_digest(supplied, expected):
                raise InvalidSnapshot("invalid report snapshot")
            payload = json.loads(_decode(encoded))
            if not isinstance(payload, dict):
                raise InvalidSnapshot("invalid report snapshot")
            issued_at = int(payload.get("issued_at", 0))
            if issued_at < time.time() - self.max_age_seconds:
                raise InvalidSnapshot("report snapshot expired; generate a new report")
            return payload
        except (ValueError, TypeError, json.JSONDecodeError, binascii.Error) as exc:
            if isinstance(exc, InvalidSnapshot):
                raise
            raise InvalidSnapshot("invalid report snapshot") from exc


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
