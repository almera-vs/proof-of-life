# Risk register

Information security risks of developing and using Proof of Life. Likelihood and impact are rated Low, Medium or High. The register is reviewed at least yearly, and after any security incident.

| ID | Risk | Likelihood | Impact | Treatment | Residual | Owner |
|---|---|---|---|---|---|---|
| R1 | Agent host compromised, exposing backup credentials, the passphrase and the signing key | Low | High | Dedicated host, read-only repository credentials, key mode 0600 or owner-only ACL. See `threat-model.md` | Medium | Operator |
| R2 | Docker socket access gives root on the agent host | Medium | High | Dedicated host. Only the agent's account gets the socket group. A remote daemon over plain TCP is refused | Medium | Operator |
| R3 | A false "pass": a backup reported restorable that is not | Low | High | Fail-closed verdict and fault-injection suite, on every supported major in CI | Low | Maintainer |
| R4 | Customer data leaks into reports, logs or notifications | Low | High | Redaction, value hashing, and sentinel tests after every test drill | Low | Maintainer |
| R5 | Evidence altered to hide a failed drill | Low | High | Signed hash chain and head file, plus anchors kept outside the agent's reach (`--min-seq`) | Low, if anchors are kept | Operator |
| R6 | A malicious or vulnerable dependency | Low | High | `go.sum`, pinned actions, Dependabot, govulncheck, CodeQL, SBOM | Low | Maintainer |
| R7 | Floating base images change behaviour, or carry a vulnerability | Medium | Medium | Accepted. Versions used are recorded in every evidence record | Medium, accepted | Maintainer |
| R8 | No second reviewer, so a defect or a malicious change goes unseen | Medium | High | CI gates, fuzzing and tests | Medium, open | Maintainer |
| R9 | Unsigned Windows executable is swapped in transit | Low | Medium | `SHA256SUMS` and build provenance on every release (`gh attestation verify`) | Low | Operator |
| R10 | Restored production data remains on the agent host's disk | Medium | Medium | Volumes removed after every drill. Full-disk encryption recommended | Low, with encryption | Operator |
| R11 | The drill loads production, through fingerprint queries | Low | Low | Read-only session with statement and lock timeouts, run after backups | Low | Operator |
| R12 | A hostile restored database stalls or attacks the sandbox | Low | Medium | No network or capabilities, resource limits, and a time limit on the checks phase | Low | Maintainer |
| R13 | The ISO and regulatory mapping is wrong, so an audit relies on it wrongly | Medium | Medium | Marked for confirmation, and sources cited in `docs/controls.md` | Medium until reviewed | Compliance reviewer |
| R14 | Code produced with AI-assisted tooling contains a defect that automated gates miss | Medium | Medium | The same CI gates, fault-injection and fuzz tests as every change | Medium | Maintainer |
