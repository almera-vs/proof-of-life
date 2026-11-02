# Security policy

## Reporting a vulnerability

Report it privately through GitHub at https://github.com/almera-vs/proof-of-life/security/advisories/new. Do not open a public issue. The report stays visible only to you and the maintainer until an advisory is published.

Include what you found, how to reproduce it, and the version (`pol version`).

## What to expect

Response targets:

| Step | Target |
|---|---|
| Acknowledgement | 5 working days |
| Assessment and severity | 10 working days |
| Fix or mitigation, critical | 30 days |
| Fix or mitigation, other | 90 days |

Fixes are released as a new version, with an advisory published on this repository.

## Supported versions

Only the latest release receives security fixes.

## Scope

In scope:
- the `pol` binary
- the container image built from this repository
- the deployment examples in `deploy/`

Out of scope:
- PostgreSQL, pgBackRest, Docker and other third-party software
- weaknesses in your own deployment, which `docs/threat-model.md` covers
