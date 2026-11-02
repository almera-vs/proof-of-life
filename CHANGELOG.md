# Changelog

All notable changes. Versions follow semantic versioning.

## 0.1.0 — 2026-11-02

First release.

### Drills
- Restore the latest pgBackRest backup, from S3-compatible storage or a POSIX path, or the latest pg_dump archive in custom or directory format, into an isolated Docker sandbox.
- Point-in-time recovery to the latest WAL, a time or an LSN, across timeline switches.
- Twelve checks, from backup freshness to measured RTO.
- PostgreSQL 14, 15, 16, 17 and 18.

### Evidence and reporting
- Hash-chained, ed25519-signed evidence log, verified offline. It survives a crash during writing.
- JSON and self-contained HTML reports that print to A4, with a controls table for DORA, ISO/IEC 27001, SOC 2 and NIS2.
- Notifications by webhook, Slack and SMTP, and Prometheus metrics.

### Platforms
- Linux amd64 and arm64, and Windows amd64.
- A distroless container image that runs as non-root.

### Security
- The production role is read-only, and every session it opens is forced read-only.
- The sandbox has no network, no capabilities, a read-only root and resource limits.
- No customer data in output: values in PostgreSQL error messages are redacted.
- A remote Docker daemon over unencrypted TCP is refused.
- The signing key is owner-only, and refused if others can read it.
- SMTP requires TLS, unless the relay is local or plaintext is allowed explicitly.
- Every release carries checksums, an SPDX SBOM and build provenance.
