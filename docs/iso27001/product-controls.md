# Controls the product helps you operate

How Proof of Life supports controls in **your** ISMS. "Your part" is what the product cannot do for you. Control numbers and titles are from ISO/IEC 27001:2022 Annex A.

| Control | What the product does | Record it leaves | Your part |
|---|---|---|---|
| **A.8.13** Information backup | Restores the latest backup into an isolated sandbox on your schedule. It proves the backup is fresh, intact, restorable, recoverable to a point in time, structurally and logically correct, free of corruption, and recoverable within the RTO target. | Signed evidence log, per-run report | Backup policy and schedule, off-site copies, retention, and deciding the drill frequency |
| **A.5.30** ICT readiness for business continuity | Measures the real recovery time against your RTO, every drill. | `rto.within_target` in each report, metrics | Setting RTO targets from your business impact analysis |
| **A.5.29** Information security during disruption | Drills run with the same confinement as normal operation, so proving recovery does not weaken security. | Container settings, tested by `TestSandboxConfinement` | Restoring under incident conditions, which a drill does not simulate |
| **A.5.28** Collection of evidence | Hash-chained, signed, append-only records that verify offline. Deletion, editing and reordering are detected. | `evidence.jsonl`, `pol evidence verify` | Keeping the public key and sequence numbers where the agent cannot write |
| **A.5.33** Protection of records | Records cannot be altered unnoticed. Reports are written atomically, with mode 0640. | Evidence log and its head file | Retention period, and copies to records storage |
| **A.5.34** Privacy and protection of PII | Only counts, hashes, names and timings leave the sandbox. Non-numeric assertion values are hashed. Error messages are stripped of quoted values. | Tested by `RequireNoCustomerData` after every test drill | The sandbox host holds full copies of production data during a drill, so protect it like production |
| **A.8.2** Privileged access rights | The production role is read-only and limited to the tables you list, and every session is forced read-only. The heartbeat writer, if enabled, can touch one table. | `deploy/sql/roles.sql`, `deploy/sql/heartbeat.sql`, `pol validate` flags excess privileges | Docker socket access equals root on the agent host: restrict who can log in there |
| **A.8.3** Information access restriction | The signing key is created owner-only, with mode 0600 on Linux and an owner-only ACL on Windows, and refused if others can read it. | `pol validate` | Access to the reports directory |
| **A.8.6** Capacity management | Measured sizing for a 20 GB database is in `docs/operations.md`. | Phase timings in each report | Disk on the agent host: at least the database size plus WAL to the end of the archive |
| **A.8.10** Information deletion | Every sandbox container and volume is removed after each drill, including on failure, panic and signal, and `pol gc` removes what a killed drill left. | Teardown phase in each evidence record | Removing a Docker volume does not overwrite the disk blocks. Use full-disk encryption on the agent host |
| **A.8.11** Data masking | Not provided. A drill restores real data, as it must to prove the backup. | — | Treat the agent host as production |
| **A.8.12** Data leakage prevention | The server container has no network. Only short tool jobs reach backup storage, and nothing leaves but results. There is no telemetry. | `docs/threat-model.md` | Network rules on the agent host |
| **A.8.15** Logging | Structured JSON logs on stderr, without secrets or row data. | Your log collector | Collecting and retaining the logs |
| **A.8.16** Monitoring activities | Exit codes, notifications on failure (webhook, Slack, email) and Prometheus metrics. A notification that cannot be delivered makes the run exit 4. | `notify` configuration, metrics textfile | Alert routing, and watching for drills that stop running |
| **A.8.17** Clock synchronization | Timestamps come from the agent host's clock. | Timestamps in evidence | NTP on the agent host |
| **A.8.20** Networks security, **A.8.22** Segregation of networks | Network isolation per container: none for the server, and the restore network only for tool jobs. A remote Docker daemon over plain TCP is refused. | Container settings | Firewalling the agent host |
| **A.8.24** Use of cryptography | ed25519 signatures and SHA-256 chaining. TLS to object storage is verified by default. `pol validate` flags an unverified database connection. | `docs/threat-model.md` "Evidence keys" | Key custody, rotation, and requiring `sslmode=verify-full` |
| **A.8.34** Protection of information systems during audit testing | Production access is read-only, with a 10 minute statement limit and a 5 second lock limit, and is used only to capture the fingerprint. The restore itself runs elsewhere. | `internal/fingerprint/capture.go` connection settings | Scheduling the capture after backups, off peak |

## The report's control table

Each report lists DORA Art. 12(2), ISO/IEC 27001:2022 A.8.13, SOC 2 A1.3 and NIS2 Art. 21(2)(c), with the checks that support each one. A control shows as evidenced only when the restore itself was proven and no supporting check failed. The mapping and its sources are in [../controls.md](../controls.md).
