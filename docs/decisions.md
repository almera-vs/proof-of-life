# Decisions

Design choices, with the reason for each.

## Repository and tooling

- **Licence: MIT with the Commons Clause.** Anyone may use, copy and modify the software, but not sell it or a service built mainly on it, and there is no warranty.
- **Source files carry no explanatory comments.** Lines the toolchain reads stay: build constraints, embeds and lint suppressions. The example configuration that `pol init` writes keeps its comments, because it is user documentation. Rationale lives in this file and in `docs/`.
- **Windows is supported through Docker Desktop's named pipe,** using Microsoft's `go-winio`. Process checks, key permissions and console colours have Windows versions.

- **CLI parsing uses the standard library `flag` package.** It keeps the dependency list short, and the command set is small.
- **YAML uses `go.yaml.in/yaml/v3`.** It is the maintained continuation of `gopkg.in/yaml.v3`, which is archived.
- **Docker is reached through a small hand-written Engine API client,** pinned to API v1.44, the oldest that current Engine releases accept. The official client pulls in a large dependency tree for the dozen endpoints this agent uses.
- **S3 for pg_dump archives uses `minio-go`,** which handles signing and credentials for any S3-compatible store.
- **testcontainers is a test-only dependency,** behind the `integration` build tag, so it does not reach the binary.
- **MinIO test images come from `cgr.dev/chainguard/minio`.** `minio/minio` and `quay.io/minio/minio` could no longer be pulled when this was built. It is still MinIO.
- **Tests run on Linux.** The binary targets Linux. On a Windows workstation the tests run inside WSL2, next to the Docker socket.
- **Milestones 3 to 5 share one commit, as do 6 and 7.** Their checks and wiring were developed together, and splitting them would have produced commits that do not build.

## Configuration

- **`drill.max_age` is optional and defaults to 26h.** The reference configuration omits it, and `backup.freshness` needs a value. 26 hours suits a daily backup with some slack.
- **Unknown YAML keys are errors, reported with their dotted path.** A misspelt `rto_target` silently falling back to a default would give false comfort.
- **Extra optional fields beyond the reference configuration:** `source.pattern`, `source.tool_image`, `source.repo.{endpoint,port,uri_style,verify_tls}`, `sandbox.{restore_network,superuser}`, `fingerprint.dir`, `fingerprint.heartbeat.dsn` and `metrics.textfile`. A unit test keeps the reference configuration parsing unchanged.
- **`sandbox.network` accepts only `none`.** The server never needs a network, and object storage access is served by `restore_network`, which applies only to short jobs.
- **Point-in-time recovery is rejected for `pgdump` at validation,** since an archive holds one point in time.

## The interfaces

- **`Restore` takes a `sandbox.Instance`, rather than a `Sandbox`.** Provisioning is its own timed phase before restore, so by then the source needs the provisioned environment, not the means to make one.
- **`BackupSource` gains `Verify`, and physical sources implement a separate `Recoverer`.** `Verify` runs after the timed phases, so a slow verification does not inflate RTO. Keeping `Recoverer` separate means logical sources do not need an empty method.
- **`Sandbox` keeps exactly `Create` and `Destroy`.** An `Instance` is a data volume, plus jobs and a server on it, and everything labelled with the instance goes when it is destroyed.
- **The checks are values of one small type,** which adds `Severity()` and `Proves()` through an optional `Described` interface, leaving the `Check` interface itself minimal.

## Restore mechanics

- **Two container images share a volume, and the server replays with no network.** The official image has no pgBackRest, and the server must not reach the network. So WAL is fetched by tool jobs before the server starts. The cost is that a time or LSN target still fetches all WAL up to the end of the archive, since nothing maps a time to a segment beforehand. That is counted in RTO, and it can overstate RTO for targets far before the end of a long archive.
- **The tool image is built on demand from an embedded Dockerfile,** unless `source.tool_image` is set. No registry is needed to get started.
- **Production's server configuration is replaced whole in the sandbox.** It can reference paths, certificates and preload libraries that do not exist there. `hot_standby` is off, which removes the requirement to match the primary's connection limits during recovery.
- **Extensions needing `shared_preload_libraries` are not loaded,** and missing extensions or locales in the image fail the restore with PostgreSQL's own message and a hint. Use a custom `sandbox.image` for these.
- **A physical restore cannot notice a missing extension's files.** The catalog says the extension is there, and it only fails when used. Only a logical restore, which runs `CREATE EXTENSION`, detects it.
- **A dump of the `postgres` database drops the sandbox's empty one first,** so `--create` can bring it back with the archive's own encoding and locale. The agent connects through `template1`, which also lets it drill clusters where `postgres` has been dropped.
- **POSIX repositories are read through a group, set with `source.repo.read_gid`.** Jobs run as uid 999 to share the data volume with the server, which is usually not the repository's owner. A permission failure is an infrastructure error naming this setting.
- **The superuser name** defaults to `postgres`, is overridden by `sandbox.superuser`, and is overridden again by the bootstrap role recorded in the fingerprint.
- **A pg_dump restore uses `--no-owner --no-privileges`,** because production's roles do not exist in the sandbox. Owners and grants are left out of the schema hash for the same reason.

## Judging results

- **The checks phase has a time limit:** `restore_timeout` plus the amcheck budget. A hostile or unexpectedly large restored database could otherwise hold a drill, and every later scheduled drill, forever. A check that runs out of time fails.
- **Implausible archive headers are damage.** A header naming a PostgreSQL version outside 8 to 99, or a creation year outside 1996 to 9999, is reported as unreadable. Fuzzing found that a damaged header could otherwise send the drill to pull an image that does not exist.

- **An archive with an empty table of contents fails `backup.integrity`,** even if it restores cleanly, as a dump of an empty database does. An empty backup is what a broken backup job leaves behind, and passing it would be the worse mistake.
- **Encoding, locale and extensions are compared along with the schema.** A difference in the first two, or a missing extension, fails `schema.fingerprint`. A different extension version alone warns, because a logical restore creates the image's default version.
- **Tablespace placement is left out of the schema hash.** A logical restore uses `--no-tablespaces` on purpose, so it is not a difference.
- **A hole in the WAL archive past a reached time or LSN target is a warning, not a failure.** This drill succeeded, but a later recovery would stop at it. At target `latest` the same hole fails, even if the server starts.
- **A missing fingerprint fails when a fingerprint section is configured,** and those checks are skipped when none is. Skipping would let a broken capture job look like a pass.
- **A fingerprint from another backup is still used when none matches exactly, and the report says so.** The "table dropped after the fingerprint" fault scenario depends on this. It can only cause a false failure, never a false pass.
- **The tolerance on estimated counts is the configured fraction, plus the rows production had changed since its last analyze, plus a floor of 10 rows.** Production's estimate cannot be better than that, and failing on noise would train people to ignore the check. The tolerance is shown in every mismatch.
- **Live tables and exact counts:** the fingerprint is captured after the backup, while production keeps changing, so an exact count on a busy table will differ. List only slow-changing tables in `exact_count_tables`. For append-only tables use an assertion bound to `:backup_stop_time`, which both sides evaluate with the same value. The reference configuration does this.
- **Heartbeat window is `[T - interval - 5s, T]`.** The 5 second grace is for writer jitter, since a tick is never exactly on time.
- **The heartbeat has a subcommand, `pol fingerprint heartbeat`,** because something has to write it. It is a plain loop with no scheduling of its own, so it does not amount to the out-of-scope daemon.
- **`pg_amcheck` running out of its time budget is a warning.** It found nothing, but it did not finish.
- **Exit codes:** an infrastructure error wins and gives 4, since no judgement was reached. Failing to write evidence or deliver a notification gives 4 when the drill otherwise passed, and 1 stays when checks failed. A result nobody receives is the GitLab failure mode.
- **`pg_dump` version detection.** Modern `pg_dump` refuses a newer server outright, so real archives cannot show an older tool in their header. The failure actually leaves an empty file or a stale archive. So `tooling.version_drift` fails on an unreadable header as well as on an older tool, and on a backup whose major is behind the fingerprint's.
- **Backup time for pg_dump is the older of the archive header's time and the file's time.** The header has local time with no zone, and copying can refresh a file time. Taking the older can understate freshness but never overstate it.

## Measuring RTO

- **Fetching images does not count towards RTO.** Building the tool image and pulling a sandbox image are recorded as their own `prepare_images` phase, outside the clock. A slow registry must not read as a slow restore, since images already sit on a prepared host. A first drill on an empty host measured 17.6 seconds too long before this.

## Evidence

- **A signed head file sits beside the log.** A hash chain alone cannot show that its newest records were removed, and deletion must be detected. `--min-seq` covers rollback of both files together.
- **`pol run` refuses to append to a damaged log,** exiting 4. Continuing would launder a deletion into a valid-looking chain.
- **A log may run ahead of its head, but never fall short of it.** A crash can fall between writing a record and updating the head. Treating that as deletion would block every later drill on an honest log. Each extra record has its own signature, so nobody without the key can add one. `verify` passes with a note, and the next drill brings the head up to date.
- **An incomplete last line is moved aside, not deleted.** A record cut off by a crash is unsigned and was never a record. `pol run` keeps it in `<log>.torn-<time>` and continues. A head naming that record still means deletion.
- **A new log gets its head before its first record,** so a crash during the first append needs no special case, and a log with no head always means the head was removed.
- **"Chain intact" in a report means checked.** Before appending, the run verifies links, and signatures for every record under the key it holds. Records under an older key can only have their links checked, and the report then says so.
- **The evidence lock is an advisory `flock`.** The kernel drops it when a process dies, so a killed drill cannot block the next one.
- **Lines must match the signed bytes exactly,** so verification rejects reformatting and added fields, not only changed values.

## The report

- **Fonts use a system fallback.** IBM Plex is named first and used if installed. Embedding it would add hundreds of kilobytes to every report, and a fallback is acceptable.
- **The report shows no "next drill" time.** Scheduling happens outside the tool, so the agent does not know, and every number in the report must come from the run.
- **"Verify evidence" links to the evidence section, and "Download PDF" opens the print dialog.** The page must work with no server, and it has no other way to produce a PDF.
- **"What needs attention" is added after the key figures when something failed.** A non-engineer needs the reason first.
- **"Not proven" is a separate headline for infrastructure errors,** so that a broken environment does not read as a broken backup.
