# Raspberry Simple DNS Reporter

A lightweight, on-demand web report built for small Raspberry Pi installations. It reads Pi-hole's long-term DNS history, translates domains into human-readable services, and optionally enriches device names with NetAlertX.

The reporter is deliberately **not** a packet sniffer. DNS data can show that a device requested a domain, when, and how often. It cannot reveal message contents, searches, watched videos, transferred bytes, or precise app usage duration.

## MVP features

- Device selector based on recent Pi-hole clients
- NetAlertX name, vendor, type, and presence enrichment
- Last 12 hours / last 24 hours reports
- Total queries, blocked percentage, and unique domains
- Domain-to-service classification with confidence labels
- DNS activity timeline
- Service drill-down with timeline and top domains
- No background analytics, external database, telemetry, or CDN assets

## Architecture

The application is a single dependency-free Python process. Calculations happen only when a report is requested.

```text
Browser
  -> Python HTTP service
       -> Pi-hole pihole-FTL.db (read-only)
       -> Pi-hole gravity.db (read-only)
       -> NetAlertX app.db (read-only)
       -> local service_map.json
  <- HTML, JSON, CSS and JavaScript
```

Pi-hole remains the authoritative DNS source. NetAlertX remains active and is only queried for device metadata.

## Requirements

- ARM64 or x86-64 host with Docker and Docker Compose
- Pi-hole v6 persistent data directory
- Optional NetAlertX database
- The Pi-hole database must retain client and domain details (Pi-hole privacy level 0)

The included Compose file expects the Homeshield paths used by the original installation:

```text
/opt/homeshield/data/pihole
/opt/homeshield/data/netalertx/db
```

Adjust only the host-side paths if your installation differs.

## Run with Docker

```sh
docker compose build
docker compose up -d
```

The UI is then available on the Raspberry Pi itself at `http://127.0.0.1:8088`.
The default port binding is loopback-only because the MVP has no built-in
authentication. From another computer, use an SSH tunnel:

```sh
ssh -L 8088:127.0.0.1:8088 USER@RASPBERRY_PI
```

Then open `http://127.0.0.1:8088` in your local browser. Exposing the service to
the LAN or through Tailscale should be an explicit deployment choice, ideally
behind authentication.

The container:

- mounts both source directories read-only;
- runs as UID/GID `20211`, with supplemental group `1000` for the Pi-hole files;
- drops all Linux capabilities;
- uses a read-only root filesystem;
- has a 64 MiB memory limit and a 0.5 CPU limit;
- never reads NetAlertX configuration or authentication files.

Docker may discard the memory limit on hosts where memory cgroups are disabled.
The service still uses a single small Python process, but the limit must not be
treated as enforced unless `docker inspect` reports a non-zero memory limit.

If your NetAlertX or Pi-hole files use different numeric ownership, update `user`, `group_add`, and the build arguments without making the source databases world-writable.

## Run tests

No packages need to be installed:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Tests create synthetic SQLite databases in a temporary directory. They never access live Pi-hole or NetAlertX data.

## Read-only database behavior

SQLite connections use URI `mode=ro`, `PRAGMA query_only=ON`, a short busy timeout, and parameterized queries. The whole Pi-hole directory is mounted read-only so its existing WAL and SHM sidecars remain visible to SQLite.

Blocked counts follow Pi-hole's documented status values rather than assuming every non-forwarded query was blocked.

## Service classification

Rules live in [`src/dns_reporter/config/service_map.json`](src/dns_reporter/config/service_map.json). A rule maps domain suffixes to:

- service;
- company;
- category;
- confidence (`high`, `likely`, `infrastructure`, or `unknown`).

Infrastructure domains such as AWS, Cloudflare, and Akamai are intentionally not attributed to a specific app. Pull requests that improve conservative, source-backed mappings are welcome.

## Security and privacy

DNS history is sensitive. The application has no built-in user authentication in the MVP.

- Keep the default loopback-only port binding unless access controls are in place.
- Do not expose port 8088 directly to the public Internet.
- Restrict it to a trusted LAN, VPN, Tailscale, or authenticated reverse proxy.
- Never commit databases, `.env` files, logs, device exports, IP addresses, MAC addresses, tokens, or Pi-hole/NetAlertX configuration.
- The API sends `Cache-Control: no-store` and identity-bearing report selections use a JSON POST body instead of URL query parameters.

The repository's `.gitignore` and `.dockerignore` reject common database and secret-bearing files, but they are not a substitute for reviewing every commit.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
