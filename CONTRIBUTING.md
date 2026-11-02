# Contributing

Thank you for helping. A few rules keep the product trustworthy.

1. **Licence.** Contributions are accepted under the same terms as the project: MIT with the Commons Clause, as in `LICENSE`.
2. **A false pass is the worst bug.** A change that adds a check also adds a fault-injection test, in which the check fails for the right reason.
3. **No customer data in output.** Anything that can quote stored values is reduced to names, counts or hashes.
4. **CI must pass.** It runs formatting, `golangci-lint`, CodeQL, `govulncheck`, unit tests on Linux and Windows with the race detector, fuzzing, integration and fault suites on PostgreSQL 14 to 18, and the README quickstart.
5. **Write decisions down.** Record design choices, with their reasons, in `docs/decisions.md`.
6. **Report security issues privately,** as described in `SECURITY.md`.

Run the checks locally (Docker is needed for the last two):

```bash
make test
```

```bash
make lint
```

```bash
make integration
```

```bash
make fault
```

See `docs/iso27001/secure-development-policy.md` for the full rules.
