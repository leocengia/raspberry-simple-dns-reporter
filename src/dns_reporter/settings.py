from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    pihole_db: Path
    gravity_db: Path
    netalertx_db: Path
    service_map: Path

    @classmethod
    def from_env(cls) -> "Settings":
        package_root = Path(__file__).resolve().parent
        return cls(
            host=os.environ.get("DNS_REPORTER_HOST", "127.0.0.1"),
            port=int(os.environ.get("DNS_REPORTER_PORT", "8080")),
            pihole_db=Path(
                os.environ.get(
                    "PIHOLE_DB_PATH", "/sources/pihole/pihole-FTL.db"
                )
            ),
            gravity_db=Path(
                os.environ.get(
                    "PIHOLE_GRAVITY_DB_PATH", "/sources/pihole/gravity.db"
                )
            ),
            netalertx_db=Path(
                os.environ.get(
                    "NETALERTX_DB_PATH", "/sources/netalertx/app.db"
                )
            ),
            service_map=Path(
                os.environ.get(
                    "SERVICE_MAP_PATH",
                    str(package_root / "config" / "service_map.json"),
                )
            ),
        )
