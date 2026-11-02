# Proof of Life

Proof of Life proves that PostgreSQL backups restore.

On a schedule, `pol` takes the latest backup, restores it into a disposable, isolated sandbox and verifies it: from "the server starts" to "the business data is correct at a point in time". It measures the real recovery time, writes tamper-evident signed evidence for auditors, and destroys the sandbox.

Customer data never leaves the infrastructure it runs on. Reports and notifications contain only counts, hashes, names and timings. There is no telemetry.

## Download

The [Releases page](https://github.com/almera-vs/proof-of-life/releases) has a single executable for Linux (amd64, arm64) and Windows (amd64), with checksums, a software bill of materials and build provenance. The release notes show how to verify a download.

`pol` needs a running Docker Engine: Docker Desktop on Windows.

## Quick start

The demo needs only Docker with Compose. It runs PostgreSQL 17, pgBackRest and MinIO, takes an encrypted backup, and drills it. It takes a few minutes.

Start the demo. `--wait` returns once the first backup exists:

```bash
docker compose -f deploy/demo/docker-compose.yml up -d --build --wait
```

Create a signing key:

```bash
docker compose -f deploy/demo/docker-compose.yml run --rm pol evidence keygen --out /var/lib/pol/ed25519.key
```

Record the reference state of the database:

```bash
docker compose -f deploy/demo/docker-compose.yml run --rm pol fingerprint capture -c /etc/pol/drill.yaml
```

Run the drill:

```bash
docker compose -f deploy/demo/docker-compose.yml run --rm pol run -c /etc/pol/drill.yaml
```

The last line reads `RESTORABLE 12/12 checks`. The first drill also builds the pgBackRest tool image, so it takes longer than later ones.

Copy the reports to `deploy/demo/out/`, where each `<run-id>.html` opens in a browser:

```bash
docker compose -f deploy/demo/docker-compose.yml run --rm reports
```

Verify the evidence log:

```bash
docker compose -f deploy/demo/docker-compose.yml run --rm pol evidence verify --log /var/lib/pol/evidence.jsonl --pub /var/lib/pol/ed25519.key.pub
```

### A failing drill

Delete WAL from the demo repository:

```bash
docker compose -f deploy/demo/docker-compose.yml run --rm break
```

Run the drill again:

```bash
docker compose -f deploy/demo/docker-compose.yml run --rm pol run -c /etc/pol/drill.yaml
```

Copy the reports out:

```bash
docker compose -f deploy/demo/docker-compose.yml run --rm reports
```

The drill exits with code 1 and `NOT RESTORABLE`, and the new report explains the failure in plain language.

Remove the demo:

```bash
docker compose -f deploy/demo/docker-compose.yml --profile tools down -v --rmi local
```

## Setting up a drill

1. **Install** the binary from the releases page, or the container image built with `make image`. Use a dedicated host: access to the Docker socket is equivalent to root, as [docs/threat-model.md](docs/threat-model.md) explains.
   - The image runs as non-root and needs the socket's group: `docker run --group-add "$(stat -c %g /var/run/docker.sock)" -v /var/run/docker.sock:/var/run/docker.sock ...`
   - A pgBackRest repository on a POSIX path that only its group can read needs `source.repo.read_gid`.
2. **Create the read-only role** with [deploy/sql/roles.sql](deploy/sql/roles.sql).
3. **Write the configuration** with `pol init`, which produces a commented example.
4. **Create a signing key** with `pol evidence keygen --out /etc/pol/ed25519.key`. Auditors get the `.pub` file.
5. **Dry run** with `pol validate -c drill.yaml`. It checks configuration, connectivity and permissions, and restores nothing.
6. **Capture a fingerprint after each backup** with `pol fingerprint capture -c drill.yaml`, as a pgBackRest post-hook or a scheduled step.
7. **Schedule the drill.** [cron](deploy/cron/pol.cron), [systemd](deploy/systemd) and [Kubernetes CronJob](deploy/k8s/cronjob.yaml) examples are included.

[docs/operations.md](docs/operations.md) covers failed drills, key management and sizing.

## Commands

```
pol init                      write a commented example configuration
pol validate -c drill.yaml    configuration, connectivity and permissions dry run, no restore
pol fingerprint capture -c drill.yaml
pol fingerprint heartbeat -c drill.yaml   opt-in; the only feature that writes to production
pol run -c drill.yaml [--target-time ...] [--keep-sandbox-on-fail] [--strict]
pol evidence keygen --out key
pol evidence verify --log evidence.jsonl --pub key.pub [--min-seq N]
pol report show <run-id> -c drill.yaml [--format json|html]
pol gc [--all] [--dry-run]    remove orphaned sandboxes and volumes
pol version
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Pass |
| `1` | Check failure |
| `2` | Warnings only, with `--strict` |
| `3` | Configuration or usage error |
| `4` | Infrastructure error |

Logs are structured JSON on stderr. The run summary goes to stdout.

## Checks

| ID | What it proves |
|---|---|
| `backup.freshness` | The newest backup is younger than `max_age`. |
| `backup.integrity` | `pgbackrest verify` is clean, or the pg_dump archive's table of contents is readable. |
| `tooling.version_drift` | The backup tool is compatible with the server, which catches the GitLab 2017 failure mode. |
| `restore.completes` | The restore finishes without errors within `restore_timeout`. |
| `recovery.wal_continuity` | Every WAL segment up to the target exists and replays. |
| `recovery.pitr_target` | Recovery reached the requested time or LSN, confirmed by a heartbeat when enabled. |
| `server.starts` | The server accepts connections, is promoted, and runs the expected version. |
| `schema.fingerprint` | The restored schema, encoding, locale and extensions match production. A mismatch comes with a readable diff. |
| `data.row_counts` | Exact-count tables match exactly, and estimated counts fall within tolerance. |
| `data.assertions` | Each configured query returns its expected value. |
| `integrity.amcheck` | `pg_amcheck` finds no heap or btree corruption within its time budget. |
| `rto.within_target` | The measured recovery time is at most `rto_target`. |

**Supported:**
- PostgreSQL 14 to 18
- pgBackRest repositories on S3-compatible storage or a POSIX path
- pg_dump archives in custom or directory format, from S3-compatible storage or a local path
- Docker on Linux, and Docker Desktop on Windows

## Reports and evidence

Each run writes `<run-id>.json` and a self-contained `<run-id>.html`, which prints to A4. A report contains:
- an executive summary
- per-check detail
- a table mapping checks to DORA Art. 12(2), ISO/IEC 27001:2022 A.8.13, SOC 2 A1.3 and NIS2 Art. 21(2)(c)

[docs/controls.md](docs/controls.md) explains the mapping and its sources.

The evidence log is append-only JSONL, hash-chained and signed with ed25519. `pol evidence verify` works offline and detects any edit, reordering or deletion. [docs/operations.md](docs/operations.md) describes anchoring sequence numbers outside the agent host, which also protects against rollback.

## Measured performance

The test database was 20 GB, holding 100 million rows plus 20 million JSON documents. The sandbox had 4 CPUs and 8 GiB.

| | pgBackRest | pg_dump |
|---|---|---|
| Restore | 40 s | 6 m 30 s |
| Measured RTO | 1 m 36 s | 6 m 31 s |
| Whole drill, with all checks | 2 m 31 s | 7 m 30 s |

The full figures are in [docs/operations.md](docs/operations.md).

## Building and testing

Build the binary:

```bash
make build
```

Run the unit tests:

```bash
make test
```

Run the integration and fault-injection suites. They need Docker, and they start real PostgreSQL, pgBackRest and MinIO. `POL_TEST_PG_MAJOR` selects the PostgreSQL version, 17 by default:

```bash
make integration
```

```bash
make fault
```

## Licence

MIT with the [Commons Clause](https://commonsclause.com/): free to use, copy and modify, but not to sell, and not to sell services built mainly on it. There is no warranty. See [LICENSE](LICENSE), and [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt) for the components included. Because of the Commons Clause, this is source-available software rather than open source as the OSI defines it.

## Security

Vulnerabilities are reported privately, as described in [SECURITY.md](SECURITY.md).

## Documentation

- [Architecture](docs/architecture.md)
- [Operations](docs/operations.md)
- [Threat model](docs/threat-model.md)
- [Controls mapping](docs/controls.md)
- [ISO/IEC 27001 evidence pack](docs/iso27001/README.md)
- [Design decisions](docs/decisions.md)
- [Adding a backup source](docs/adding-a-backup-source.md)
- [Roadmap](docs/roadmap.md)
