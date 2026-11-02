# Operations

Procedures for running Proof of Life in production. This is the documented operating procedure ISO/IEC 27001:2022 A.5.37 expects.

## Daily operation

| When | What | Command |
|---|---|---|
| After each backup | Record the reference state | `pol fingerprint capture -c drill.yaml` |
| On schedule, e.g. nightly | Run the drill | `pol run -c drill.yaml` |
| Daily | Remove leftovers from killed drills | `pol gc` |
| Monthly, or before an audit | Verify the evidence log offline | `pol evidence verify --log evidence.jsonl --pub key.pub --min-seq N` |

Schedule with cron, a systemd timer or a Kubernetes CronJob. See `deploy/`.

## When a drill fails

Read the last line of the run and the report's "What needs attention" section.

| Exit | Meaning | First step |
|---|---|---|
| 1 | The backup could not be proven restorable | Read the failing check's reason. Treat it as a backup incident: until the next drill passes, assume you cannot restore |
| 4 | Not proven: the environment failed | Check Docker, storage reachability and disk space. Fix the cause and run the drill again. This says nothing about the backup |
| 3 | Configuration or usage error | `pol validate -c drill.yaml` names the field |
| 2 | Warnings, with `--strict` | Read the warning. The backup restored |

Keep a failed sandbox for investigation with `--keep-sandbox-on-fail`. Remove it afterwards with `pol gc --all`.

## Key management

- Create the key once with `pol evidence keygen --out /etc/pol/ed25519.key`. It is created owner-only.
- Give auditors the `.pub` file. Keep a copy of it outside the agent host.
- Back up the private key as you would any signing secret. If it is lost, the existing log can still be verified with the public key, but new records need a new key.
- **Rotation:** create a new key and point `evidence.sign_key` at it. Keep every old public key, and pass all of them to `pol evidence verify` with a repeated `--pub`.
- **Suspected compromise:** stop drills, create a new key, and record the last sequence number the old key signed. Treat later records under the old key as untrustworthy.

## Anchoring the evidence

Someone with the key could rewrite the whole log. To limit that, copy the sequence number from each filed report, or the head file, somewhere the agent cannot write. Later, `pol evidence verify --min-seq N` proves no record up to N was removed.

## Sizing

Measured on 2026-11-02, on 8 vCPU, 32 GB RAM and NVMe storage under WSL2. The database was 20 GB: 100 million pgbench account rows and 20 million orders with JSON documents and a GIN index. The backup was a full pgBackRest backup to MinIO, compressed with zstd and encrypted, followed by 5 minutes of write traffic. The sandbox had 4 CPUs and 8 GiB.

| | pgBackRest, physical | pg_dump, directory format |
|---|---|---|
| Backup or dump size | 20 GB, compressed and encrypted in the repository | 1.2 GB with `-j4` |
| Restore | 39.7 s | 6 m 30 s, including index builds |
| WAL replayed | 285 segments in 54.2 s | none |
| **Measured RTO** | **1 m 36 s** | **6 m 31 s** |
| Checks: verify, schema, counts, amcheck | 51.7 s, of which amcheck 34.4 s | about 1 m, of which amcheck 44.3 s |
| Whole drill | 2 m 31 s | 7 m 30 s |
| Sandbox peak memory | 5.0 GiB of 8 GiB | 6.9 GiB of 8 GiB |
| Sandbox peak disk | 26.4 GB | 22.9 GB |
| Agent process memory | 32 MB | similar |
| Result | 12 of 12 checks passed | 10 of 10 applicable checks passed |

The scripts are in `deploy/demo/load/`. `load.sh` generates the data inside the demo database, and `big.yaml` is the drill.

A finding from the same run: loading 20 GB in one go produced WAL faster than the demo's synchronous `archive-push` could store it, and the first backup failed because its WAL was not archived within pgBackRest's 60 seconds. That is a pgBackRest setting, not a Proof of Life one. For large loads, use asynchronous archiving (`archive-async=y`, with `process-max`). Throughout, Proof of Life drilled the newest backup that had completed.

**Rules of thumb:**
- **Disk on the agent host:** the database size, plus WAL from the backup to the end of the archive, plus headroom. The restored copy and the fetched WAL both sit in the sandbox volume until teardown.
- **Memory:** the sandbox's `memory` setting caps the server. shared_buffers is set to a quarter of it.
- **Time:** restore scales with database size and `cpus`, which sets pgBackRest's `--process-max`. Recovery scales with the WAL written since the backup, and amcheck with total relation size.

## Upgrades

- Read `CHANGELOG.md`, replace the binary, and run `pol validate -c drill.yaml` before the next scheduled drill.
- After a PostgreSQL major upgrade, take a new full backup and capture a new fingerprint. Until then, `tooling.version_drift` fails by design.
