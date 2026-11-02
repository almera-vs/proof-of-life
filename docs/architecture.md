# Architecture

Proof of Life is a single static binary that runs on your schedule, does one drill and exits. It has no daemon and no database. Its state is three kinds of file: fingerprints, the evidence log and reports.

## Packages

| Package | Responsibility |
|---|---|
| `cmd/pol` | Commands, exit codes, terminal summary |
| `internal/config` | YAML loading, validation with dotted field names, secret references |
| `internal/source` | The `BackupSource` interface, with `pgbackrest/` and `pgdump/` |
| `internal/sandbox` | The `Sandbox` interface, with `docker/` on the Engine API |
| `internal/fingerprint` | Capture and comparison of the production reference state, and the heartbeat writer |
| `internal/checks` | The `Check` interface and the twelve v1 checks |
| `internal/drill` | The state machine, phase timing, verdict and teardown |
| `internal/evidence` | The hash-chained, signed log and its offline verifier |
| `internal/report` | The JSON report, the self-contained HTML page and the controls table |
| `internal/notify` | Webhook, Slack and SMTP |
| `internal/obs` | Structured logging, Prometheus textfile metrics, formatting |

## One drill

```
select_backup → describe → provision_sandbox → restore → recover → start → checks → evidence → report → notify → teardown
```

- **Measured RTO** runs from the start of `select_backup` to the end of `start`, when the server is ready to serve. Checks do not count: `pgbackrest verify` and `pg_amcheck` are proofs, not part of a recovery. Neither does fetching images, which is timed as its own `prepare_images` phase.
- **A problem with the backup never aborts the drill.** The failure is recorded and the steps that do not depend on it still run, so the report explains as much as it can. `source.Failure` marks a problem with the backup. Any other error means the environment failed, which is reported as "not proven" with exit code 4.
- **Teardown** runs from a deferred function, on a context detached from cancellation. It covers success, failure, panic, SIGINT and SIGTERM. SIGKILL cannot be caught, so everything is labelled `pol.run_id` and `pol gc` removes what a dead process left. `gc` skips a sandbox whose owner is still alive, or that belongs to another host, unless given `--all`.
- **The verdict fails closed.** A pass requires `restore.completes` and `server.starts` to have actually passed. Skipped checks are stated in the report and never counted as passes.

## The sandbox

The official `postgres` image has no pgBackRest, and the server must have no network. So one sandbox is a private data volume with two kinds of container on it:

```
             object storage
                   ▲
                   │ short jobs only: restore_network
        ┌──────────┴───────────┐
        │  tool image jobs     │  pgbackrest restore, repo-ls, archive-get
        └──────────┬───────────┘
                   ▼
            data volume  (/var/lib/postgresql)
                   ▲
        ┌──────────┴───────────┐
        │  server container    │  postgres:{{major}}, network none
        └──────────────────────┘
                   ▲
                   │ exec through the Docker API: psql, pg_amcheck, pg_restore
                 agent
```

Every container runs as uid 999 with all capabilities dropped, `no-new-privileges`, a read-only root filesystem, tmpfs for `/tmp` and the socket directory, and CPU, memory and process limits. The agent reaches the server only by exec over the Docker API, because the server has no network to connect over.

The tool image `pol-pgbackrest:0.1.0` is built from an embedded Dockerfile if it is not present, or set with `source.tool_image`. Sandbox images must be Debian-based, with the postgres user at uid 999, like the official ones.

## pgBackRest recovery

The server replays WAL with no network and no pgBackRest binary, which takes three steps:

1. **Plan.** `pgbackrest repo-ls` lists the archive. `wal.go` walks from the backup's first segment to the newest one on the latest timeline descending from the backup, following timeline history files, and names every gap. This walk matters most at target `latest`: PostgreSQL stops at a hole and promotes without complaint, so the server alone would report success after losing data.
2. **Fetch.** A job runs `archive-get` for each planned segment into the volume. pgBackRest verifies each file's checksum on the way out, and any that fail are listed as unreadable.
3. **Replay.** Production's `postgresql.conf`, `postgresql.auto.conf`, `pg_hba.conf` and `pg_ident.conf` are replaced with sandbox versions, since they can name paths, certificates and libraries that do not exist here. `hot_standby` is off, so recovery does not require the primary's connection limits. `restore_command` copies from the fetched directory. `recovery_target_action` is `promote`.

If recovery cannot reach a requested target, PostgreSQL exits with a FATAL message, which `recovery.pitr_target` reports. Replay position is then compared with the backup's stop LSN, the target, and at `latest` the start of the newest archived segment.

Observed behaviour of pgBackRest 2.60 that the code relies on, each covered by a test: `info` and `verify` exit 0 even when they report errors, so their output is parsed and missing status fails closed; `archive-get` needs a restored `pg_control`; a wrong passphrase shows up as `FormatError` in the JSON status, with raw bytes that are stripped before parsing and never quoted.

## pg_dump restore

The archive header is parsed in Go, using the layout in `pg_backup_archiver.c`, to find the versions and the database name without needing a server of the right major. That selects the image. The archive is streamed into the volume through the Engine API's archive endpoint, a cluster is initialized, the server starts with no network, and `pg_restore --create --exit-on-error --no-owner --no-privileges --no-tablespaces` runs inside it. Owners and grants are not restored because the sandbox has none of production's roles, so the schema hash leaves them out on both sides.

## The fingerprint

The same catalog queries run on production, over a read-only `pgx` connection, and in the sandbox, through `psql --csv`. `search_path` is pinned to `pg_catalog` on both sides, so the deparsing functions print the same text. Objects belonging to extensions are represented by the extension's version. Dropped columns are handled by comparing position among live columns rather than `attnum`, which a dump legitimately changes.

A fingerprint is linked to a backup by label. When a backup has no matching fingerprint, the newest is used and the report says so, because comparing against the closest reference can produce a false failure but never a false pass.

After a physical restore, `pg_class.reltuples` just repeats production's numbers, which would prove nothing. So `data.row_counts` runs `ANALYZE` on the restored pages first and compares that.

## Evidence

Each line is a signed record, and `prev_hash` is the SHA-256 of the whole previous line, so any edit breaks both the record's own signature and the next link. Lines must match byte for byte what was signed, so added fields and reformatting are detected too.

A chain alone cannot show that its newest records were removed. So a signed head file names the last record: a shorter log disagrees with it, and an attacker without the key cannot forge a new one. A log may run ahead of its head, because a crash can fall between the two writes and every extra record is itself signed. The next drill brings the head up to date. Someone holding an older copy of both files could still roll them back together, which is why `pol evidence verify --min-seq` accepts the number from the last report you filed. `pol run` refuses to append to a log that is damaged or shorter than its head, since that would paper over a deletion.

## Report JSON

`schema_version` identifies the shape. It carries status, counts, measured RTO and target, recovery point, backup metadata, phases, per-check results and the evidence pointer, which is what a future view across many databases needs per drill.
