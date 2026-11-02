# Development controls

How Proof of Life is built, mapped to ISO/IEC 27001:2022 Annex A. "Evidence" names a file or check an auditor can inspect. Status is **In place**, **Partly** or **Not yet**.

| Control | What is in place | Evidence | Status |
|---|---|---|---|
| **A.5.3** Segregation of duties | A single maintainer writes, reviews and releases. Branch protection requires every CI check to pass before any change reaches `main`, for administrators too. | `.github/CODEOWNERS`, branch protection settings | Partly: single maintainer |
| **A.5.8** Information security in project management | Security requirements were set before development started: least privilege, no data egress, tamper-evident evidence. Each stage of development included its security work. | `docs/threat-model.md`, `docs/decisions.md` | In place |
| **A.5.9** Inventory of information and other associated assets | Every release carries a software bill of materials listing each compiled-in module and version. | Release asset `pol.spdx.json`, `THIRD_PARTY_NOTICES.txt` | In place |
| **A.5.21** Managing information security in the ICT supply chain | Dependencies are pinned and hashed in `go.sum`. CI actions are pinned to exact commits, not tags. Dependabot proposes updates weekly. Base container images and the pgBackRest tool image are **not** pinned, an accepted decision recorded in `docs/decisions.md`. | `go.sum`, `.github/workflows/*.yml`, `.github/dependabot.yml` | Partly: base images are not pinned |
| **A.5.32** Intellectual property rights | The licence is MIT with the Commons Clause. Third-party licences are reproduced in full and regenerated from the actual binary for each release. | `LICENSE`, `THIRD_PARTY_NOTICES.txt`, `scripts/notices.sh` | In place |
| **A.5.35** Independent review of information security | No external assessment has been carried out yet. | — | Not yet |
| **A.5.36** Compliance with policies, rules and standards | The secure development policy's automatic rules are enforced in CI on every change. A change that breaks them cannot merge. | `.github/workflows/ci.yml` | In place |
| **A.8.4** Access to source code | Read access is public. Write access is limited to the maintainer. Merging to `main` requires passing CI. | Repository settings, branch protection | In place |
| **A.8.8** Management of technical vulnerabilities | `govulncheck` runs in CI on every change. CodeQL runs on every change and weekly. Dependabot updates dependencies. `SECURITY.md` sets reporting and response targets. At the last review, no known vulnerability was reachable from the agent's code. One vulnerability, with no fix yet, sits in a test-only dependency that is never compiled into the agent. | CI `vulnerabilities` job, CodeQL alerts, `SECURITY.md` | In place |
| **A.8.9** Configuration management | Configuration is validated strictly: unknown keys and invalid values fail with the field's name, and secrets cannot be written inline. CI configuration is version controlled. | `internal/config`, `pol validate` | In place |
| **A.8.25** Secure development life cycle | The written policy covers requirements, design, coding, testing, review and release. Every rule a machine can check runs automatically. | `secure-development-policy.md`, CI | Partly: single maintainer (A.5.3) |
| **A.8.26** Application security requirements | Stated requirements: least privilege, no customer data in output, network isolation, secrets by reference only, tamper-evident records. Each has a test. | `docs/threat-model.md` "What the tests enforce" | In place |
| **A.8.27** Secure system architecture and engineering principles | Fail closed: a pass requires a proven restore, and anything missing is a failure, never a pass. Least privilege. Defence in depth: read-only role, read-only session and timeouts. Isolation: the server has no network, no capabilities and a read-only root. | `docs/architecture.md`, `docs/decisions.md` | In place |
| **A.8.28** Secure coding | Every change passes `golangci-lint` (including `gosec`, `staticcheck` and `errorlint`), the race detector, and CodeQL's security-and-quality queries. Every parser of untrusted input is fuzzed. SQL is built from validated identifiers or fixed literals, and external commands run without a shell or with arguments passed positionally. | `.golangci.yml`, CI `fuzz` job, `*/fuzz_test.go` | Partly: single maintainer |
| **A.8.29** Security testing in development and acceptance | Fault-injection suite: 14 scenarios on PostgreSQL 14 to 18, each required to fail on the correct check. Container confinement, read-only roles, redaction of customer data and evidence tampering are each tested end to end. The README quickstart runs on a clean machine. A drill was run on about 20 GB of generated data. | `test/fault`, `test/integration`, `test/quickstart.sh`, CI | In place |
| **A.8.30** Outsourced development | No development is outsourced. Development tooling, including AI-assisted coding, produces changes that pass the same CI gates as any other change. | Git history, CI | In place |
| **A.8.31** Separation of development, test and production environments | Development and CI use throwaway containers and synthetic data only. Tests never connect to production. | `test/harness`, CI | In place |
| **A.8.32** Change management | Every change is a commit on a branch, merged to `main` only after CI passes. Releases come only from version tags, through the release workflow, with notes in `CHANGELOG.md`. Tags are not cryptographically signed. Instead, each release carries a build provenance attestation, which binds the binaries to the commit and workflow that built them. | Git history, `.github/workflows/release.yml`, `CHANGELOG.md` | In place |
| **A.8.33** Test information | Tests use generated data. A sentinel value in the test data proves that no customer-like value reaches output. | `test/harness/harness.go` `Seed`, `RequireNoCustomerData` | In place |

## Release integrity

Every release publishes:
- the binaries
- `SHA256SUMS`
- an SPDX software bill of materials
- a build provenance attestation, which proves the binary was built by this repository's workflow from a specific commit

Verify a download with:

```bash
gh attestation verify pol-0.1.0-linux-amd64 --repo almera-vs/proof-of-life
```

The Windows executable is not Authenticode-signed, so Windows SmartScreen may warn on first run. The executable is not yet code-signed.
