# Secure development policy

This policy supports ISO/IEC 27001:2022 A.8.25, A.8.26, A.8.27, A.8.28, A.8.29, A.8.32 and A.8.8.

## 1. Scope
All code, configuration, CI workflows and documentation in this repository, and every release built from it.

## 2. Requirements before code
- A change that affects what the agent can access, what leaves the sandbox, or how evidence is written updates `docs/threat-model.md` in the same change.
- Design choices are recorded in `docs/decisions.md`, with their reasons.

## 3. Design rules
- **Fail closed.** If something cannot be proven, the result is a failure or "not proven", never a pass.
- **Least privilege.** Production access is the read-only fingerprint role. Sandbox containers have no capabilities, no network unless they must reach backup storage, a read-only root and resource limits.
- **No customer data in output.** Only counts, hashes, names and timings. Text from PostgreSQL that can quote values is redacted before it is shown.
- **Secrets by reference only,** through `env:` or `file:`, and never logged.
- **No new network destinations.** The agent talks only to Docker, backup storage, the fingerprint database and configured notification targets.

## 4. Coding rules, enforced in CI on every change
- `gofmt` and `golangci-lint`, with `errcheck`, `errorlint`, `gosec`, `govet`, `staticcheck` and `unused`. Each exclusion is listed in `.golangci.yml` with its reason.
- CodeQL security-and-quality queries.
- `govulncheck`: the agent's code may not reach a known vulnerability.
- Unit tests with the race detector, on Linux and Windows.
- A fuzz test for every parser of untrusted input, run in CI.
- SQL may contain only fixed text, validated identifiers, or literals produced by the agent itself.
- External programs run with argument lists, never by assembling a shell command from data.

## 5. Testing
- Every fault the product claims to detect has a test that injects it into a real backup and requires a failure from the correct check.
- The happy path passes on every supported PostgreSQL major.
- Tests use generated data only, never production data.

## 6. Review and change
- Every change goes through a branch, and merges to `main` only after CI passes.
- Changes touching `internal/sandbox`, `internal/evidence`, `internal/source` or `deploy/sql` are reviewed by a second person when one is available. With a single maintainer this is recorded as risk R8 in `risk-register.md`.
- Releases are cut only from tags through `.github/workflows/release.yml`, with an entry in `CHANGELOG.md`.

## 7. Vulnerabilities
Reports go through GitHub private vulnerability reporting, as described in `SECURITY.md`. Response targets: acknowledge within 5 working days, and fix or mitigate critical issues within 30 days and others within 90.

## 8. Dependencies
- Updated through Dependabot pull requests, which pass the same CI as any change.
- A new dependency must be well maintained, carry a licence compatible with `LICENSE`, and earn its place over writing the code.
- Third-party notices are regenerated for every release.
