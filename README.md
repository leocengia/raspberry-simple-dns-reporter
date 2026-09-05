# Raspberry Simple DNS Reporter

A lightweight, on-demand web report built for small Raspberry Pi installations. It reads Pi-hole's long-term DNS history, translates domains into human-readable services, and optionally enriches device names with NetAlertX.

The reporter is deliberately **not** a packet sniffer. DNS data can show that a device requested a domain, when, and how often. It cannot reveal message contents, searches, watched videos, transferred bytes, or precise app usage duration.

## MVP features

- Device selector based on recent Pi-hole clients
- Multi-device selection and aggregated reports
- Pi-hole group selection (exact IP, subnet, and MAC selectors)
- NetAlertX name, vendor, type, and presence enrichment
- 3h, 6h, 12h, 24h, 48h, and 7-day rolling reports
- Reports for a specific `Europe/Rome` calendar day, including correct 23/25-hour DST days and the current day so far
- Total queries, blocked percentage, and unique domains
- Domain-to-service classification with confidence labels
- DNS activity timeline
- Service drill-down with timeline and top domains
- Timestamped, paginated raw-query drill-down for services and review signals
- Streaming CSV and JSONL evidence exports for a service, one signal, or all signals
- LLM-ready Markdown exports for a whole report or any downloadable evidence slice
- Stable device identity with safe disambiguation of duplicate display names
- Per-service comparison between selected devices
- Seven-day historical baseline with conservative change signals
- Browser-side JSON, CSV, and print/PDF export
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

Pi-hole remains the authoritative DNS source. NetAlertX remains active and is only queried for device metadata. Every generated report fixes absolute report and baseline boundaries in `Europe/Rome`; a selected calendar day runs from local midnight to the next local midnight (or to the generation time when selecting today). Subsequent detail and export requests use a short-lived, server-signed snapshot rather than recalculating “now”. Snapshots expire after 24 hours or when the process/classifier version changes, at which point the UI asks for a new report.

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

For tailnet-only access while keeping the Docker port bound to loopback, use
Tailscale Serve:

```sh
tailscale serve --bg --http=8088 --yes 127.0.0.1:8088
```

Tailscale prints the MagicDNS URL to open from authorized tailnet devices. The
traffic remains restricted to the tailnet; do not use Funnel for DNS history.

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

- stable service and rule IDs;
- service;
- company;
- category;
- confidence (`high`, `likely`, `infrastructure/ambiguous`, or `unknown`);
- an optional infrastructure provider.

Specific rules are ordered before generic infrastructure rules. For example, an Apple/iTunes hostname delivered through Akamai preserves both Apple as the attributable service and Akamai as infrastructure. Opaque Akamai hostnames are shown as `Akamai CDN (shared infrastructure)` and are not evidence that a particular app was used.

## Device identity

The Reporter never groups devices by hostname. It prefers a stable NetAlertX/Pi-hole hardware identity, then falls back to the raw Pi-hole client. Multiple observed IPv4/IPv6 addresses are combined only when a shared stable identity supports the association. Distinct devices with the same hostname remain separate and receive a short stable suffix in the UI. Raw client/IP and identity confidence remain available in query details and exports.

## Changes and review signals

Each report compares the current window with the preceding seven days. Historical
queries are aggregated inside SQLite instead of being loaded into memory. Signals
cover domains and identified services absent from the baseline, unusually large
hourly query spikes, high blocked share, and high unclassified share.

These are review thresholds, not threat detections. A "new" item means not seen
in the seven-day baseline for the selected scope; it does not mean the domain has
never existed or is malicious.

## Export behavior

The aggregate report still supports browser-side JSON, CSV, and print/PDF. Raw query evidence uses `POST /api/exports/queries` and is serialized incrementally from read-only SQLite rows; the server does not persist files or materialize the complete export in memory. Supported scopes are one `signal_id`, all signals (deduplicated by Pi-hole query ID), or one stable `service_id`. Formats are UTF-8 CSV and JSONL/NDJSON.

Every raw row includes:

```text
query_id, timestamp_local, timestamp_utc, timestamp_epoch, timezone,
canonical_device_id, device_name, device_identity_confidence, client_key,
client_ip, domain, service_id, service_name, company, category,
infrastructure_provider, classification_confidence, classification_rule_id,
classification_version, query_type_raw, query_type_label, status_raw,
status_label, blocked, reply_type_raw, reply_type_label, reply_time, forward,
list_id, signal_ids, signal_types, report_start_local, report_end_local,
baseline_start_local, baseline_end_local
```

Fields unavailable in the installed Pi-hole schema are `null`/empty. Raw numeric codes are retained; labels are omitted unless the Reporter can state them safely. CSV values beginning with spreadsheet formula characters are prefixed with an apostrophe for safe opening; JSONL retains the original text. Timestamps use epoch seconds plus unambiguous UTC and `Europe/Rome` ISO-8601 forms, including DST offsets.

### LLM-ready Markdown

The `LLM report (.md)` action produces a self-describing Markdown evidence bundle suitable for direct upload to ChatGPT Work or local analysis with Codex CLI. Equivalent Markdown actions are available for one service, one review signal, all review signals, and a filtered query-log selection.

The file contains:

- a machine-readable schema/version, report boundaries, timezone, scope, devices, and classifier version;
- an analysis contract that states what DNS evidence can and cannot prove;
- aggregate metrics, ranked services, top domains, and conservative review signals;
- chronological JSONL activity grouped into five-minute buckets by device and service;
- exact first/last query timestamps, allowed/blocked counts, infrastructure attribution, classification confidence, and matching signal IDs/types;
- six-hour section boundaries so a long report can be analyzed in manageable chunks.

Five-minute grouping keeps repeated DNS chatter compact without losing the useful temporal bounds. The raw CSV and JSONL exports remain the authoritative per-query evidence when an exact event-by-event audit is needed. The Markdown export never includes the short-lived report snapshot token.

Codex CLI can inspect a downloaded bundle with read-only filesystem access. For example:

```sh
codex exec --sandbox read-only --skip-git-repo-check --cd /path/to/reports \
  "Analyze ./homeshield_llm-report_DEVICE_DATE.md. Follow the embedded Analysis contract, prioritize review signals and unknown/shared-infrastructure activity, and cite exact local intervals and domains."
```

`codex exec` is the supported non-interactive CLI workflow; `--cd` selects the report directory and `--sandbox read-only` prevents filesystem changes. See the [official Codex CLI command reference](https://developers.openai.com/codex/cli/reference).

DNS bundles contain private browsing metadata. They remain local until the user explicitly gives the file to Codex, ChatGPT Work, or another service.

`POST /api/queries` provides the same evidence as a bounded page (maximum 100 rows) for the UI. Both endpoints accept only server-issued snapshot tokens, known scopes/IDs, bounded text filters, known device IDs, and fixed report windows. They never accept SQL, regular expressions, or raw database predicates.

## Security and privacy

DNS history is sensitive. The application has no built-in user authentication in the MVP.

- Keep the default loopback-only port binding unless access controls are in place.
- Do not expose port 8088 directly to the public Internet.
- Restrict it to a trusted LAN, VPN, Tailscale, or authenticated reverse proxy.
- Never commit databases, `.env` files, logs, device exports, IP addresses, MAC addresses, tokens, or Pi-hole/NetAlertX configuration.
- The API sends `Cache-Control: no-store` and identity-bearing report selections use a JSON POST body instead of URL query parameters.
- Raw exports contain personal DNS history. Download and share them only as sensitive files.

The repository's `.gitignore` and `.dockerignore` reject common database and secret-bearing files, but they are not a substitute for reviewing every commit.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
