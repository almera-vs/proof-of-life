# Threat model

What the agent can reach, what an attacker gains by compromising it, and how keys are handled.

## What the agent can access

| Asset | Access | Why |
|---|---|---|
| Backup repository | Read, using the configured credentials | To restore from it |
| Decryption passphrase | Read | To restore an encrypted repository |
| Production database, fingerprint role | Read-only, with `SELECT` on listed tables | To capture the reference state |
| Production database, heartbeat role | Insert and delete on one table, opt-in | To prove point-in-time recovery |
| Docker Engine socket | Full | To create sandboxes |
| Evidence signing key | Read | To sign records |
| Restored data | Full, inside the sandbox | To verify it |
| Notification targets | Send | To report results |

## What an attacker gains by compromising the agent

Treat the host as being as sensitive as the backups themselves.

- **All backup contents.** The agent holds repository credentials and the passphrase, so a compromise is a compromise of every backup in the repository. Give it a read-only repository credential: it never needs to write, and read-only access also protects the backups from it.
- **Root-equivalent access to the host.** Access to the Docker socket is equivalent to root on that host. Run the agent on a dedicated host or VM, not on the database server.
- **Forged evidence, from then on.** With the signing key, an attacker can sign new records. They cannot silently alter earlier ones if you keep anchors elsewhere: see below.
- **A read of production's catalogs and listed tables,** and, if the heartbeat is enabled, the ability to write to that one table. Neither role can reach anything else, and the fingerprint session is read-only even if the role is later given more rights.

## Data in logs, reports and notifications

Logs, reports and notifications hold counts, hashes, names and timings. No row data. Specifically:

- Assertion results are stored and shown in the clear only if numeric. Anything else is kept only as a hash, because an assertion can select customer data.
- Schema differences do not quote function, view or trigger text, which can hold literal values.
- `pg_amcheck` details are reduced to the relation name, because its detail lines can describe stored values.
- `pg_restore` errors from `COPY` are reduced to the table name, because they can quote a row.
- A server FATAL line is shown only for startup failures, which carry paths and LSNs.
- The test suites plant a sentinel value in a table and search all output and files for it after every drill, passing or failing, including one where `pg_restore` fails on the row holding it.

Object names and row counts do appear. If those are sensitive in your environment, treat reports accordingly. Fingerprint files hold the full schema listing, including function source, so they get mode 0600 and stay on the agent's host.

## Docker endpoint

The agent reaches Docker through the local socket on Linux, or Docker Desktop's named pipe on Windows. A `DOCKER_HOST` that points to another machine over unencrypted TCP is refused, because control of the daemon is control of that host. To use a remote daemon, forward it to a local port over SSH. A loopback TCP address is accepted, and any local user who can reach that port controls Docker.

## Network

The agent connects to the Docker socket, the backup storage, the fingerprint database and the configured notification targets, and nothing else. There is no telemetry.

The server container always runs with `network: none`. Only one-shot tool jobs get a network: pgBackRest's `info`, `repo-ls`, `archive-get`, `restore` and `verify`, on `sandbox.restore_network`, for as long as they run. Those jobs hold repository credentials and encrypted data, never a running server. Pulling images goes through the Docker daemon and needs registry access, unless images are already present. The first pgBackRest drill builds the tool image, which needs the Debian and PGDG package repositories, unless you pre-build it or set `source.tool_image`.

## Data left on disk

A drill writes a full copy of the restored database to a Docker volume, and removes it afterwards. Removing a volume frees its disk blocks without overwriting them, so until they are reused the data can be recovered by anyone with raw access to that disk. Use full-disk encryption on the agent host.

## Secrets

- Secrets can only be referenced with `env:` or `file:`. An inline value is rejected at load time, and the error does not echo it.
- A resolved secret has a type that redacts itself in formatting, logs and JSON.
- Webhook URLs, which are themselves secrets, never appear in errors.
- The signing key is created readable by its owner only: mode 0600 on Linux, or an ACL for the owner and SYSTEM, with no inheritance, on Windows. On Linux, the agent refuses to use a key that other users can read.
- `pol validate` and `pol fingerprint capture` say when the fingerprint connection does not verify the database's certificate. SMTP refuses to send without TLS unless the relay is local or `allow_plaintext` is set.
- Connection strings are kept out of error messages.
- **Limitation:** repository credentials and the passphrase reach pgBackRest jobs as container environment variables, so anyone with access to the Docker socket can read them with `docker inspect` while a job runs. Socket access already implies root on the host, so this adds no new exposure, but note it if you audit the host. The containers are removed when each job ends.

## The sandbox as a boundary

Restored data may be hostile, for example if an attacker controlled production: a function could run in the sandbox server. `pg_amcheck --install-missing` and `ANALYZE` run as superuser and can trigger user code such as index expressions. The sandbox holds this: no network, no capabilities, read-only root, resource limits, non-root user. It relies on Docker's isolation; use a dedicated host if your threat model includes container escape. Assertions you configure also run there, and a restored database could return false values to them, so these checks prove a restore against production's reference, not against a compromised production.

## Evidence keys

- `pol evidence keygen` writes the private key with mode 0600 and refuses to overwrite one.
- The private key signs and stays on the agent's host. Auditors get only the public key, so they can verify offline without being able to sign. An HSM or KMS is not supported in v1.
- **What the evidence proves:** that a holder of the key wrote these records in this order, and that nothing changed afterwards.
- **What it does not prove on its own:** it does not stop someone with the key from writing false records from then on, or from rewriting the entire log. To limit this, copy the public key, and periodically the head file or the sequence number from your reports, to a place the agent cannot write. `pol evidence verify --min-seq N` then detects a rollback past that point.
- **Rotation:** generate a new key, and point `sign_key` to it. Pass every public key to verification with a repeated `--pub`.

## What the tests enforce

- `TestSandboxConfinement` watches every container of a real drill and checks its user, capabilities, read-only root, limits and network. Only tool jobs get a network, and only the restore network.
- `TestShippedRolesAreConfined` runs the shipped `roles.sql` and `heartbeat.sql`, then tries to write and to read unlisted tables through both roles. The drills in the suites capture their fingerprints through the shipped read-only role.
- **Known gap on PostgreSQL 14:** a default grant lets every role create objects in schema `public`. The shipped roles' sessions are read-only by default, and the test proves that holds, but a role that turned the default off could create a table there. Reading data and changing existing tables stay refused. `roles.sql` shows the `REVOKE` that closes this, left commented out because it affects all roles.
- The claim that the agent contacts nothing but its configured targets is **not** tested by capturing traffic. It follows from the code having no other network calls.

## Known limits

- A drill proves that a backup restored at that moment. It says nothing about the next backup.
- An estimated row count is a statistical comparison, so small differences inside the tolerance are not detected. Use `exact_count_tables` and assertions for what must be exact.
- Unlogged tables are not part of a physical backup and are left out of row comparisons.
- `integrity.amcheck` checks heap and btree only. GIN, GiST, BRIN and other index types are not verified. If it runs out of its time budget the result is a warning that says part of the database was not checked.
