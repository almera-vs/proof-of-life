# ISO/IEC 27001:2022 evidence pack

These documents support an ISO/IEC 27001 audit of an organisation that uses Proof of Life. They are not a certificate, and not a claim of compliance.

## Scope

ISO/IEC 27001 certifies an organisation's information security management system (ISMS), not software. These documents therefore cover two things:

1. **How Proof of Life is developed, tested, changed and released,** for organisations that adopt it under their ISMS. See [development-controls.md](development-controls.md).
2. **The ISMS controls the product helps operate,** chiefly A.8.13 (information backup) and A.5.30 (ICT readiness for business continuity), and the records it produces as proof. See [product-controls.md](product-controls.md).

For each applicable Annex A control, these documents state:
- what is in place
- where the evidence is
- what the product does not cover

## Contents

| Document | Purpose |
|---|---|
| [development-controls.md](development-controls.md) | Annex A controls for how Proof of Life is developed, tested, changed and released |
| [product-controls.md](product-controls.md) | Annex A controls the product helps operate, and how |
| [secure-development-policy.md](secure-development-policy.md) | The rules development follows |
| [risk-register.md](risk-register.md) | Information security risks of the product, with their treatment |
| [statement-of-applicability.md](statement-of-applicability.md) | Every Annex A control, marked applicable or not to the product, with the reason |
| [../operations.md](../operations.md) | Operating procedures (A.5.37) |
| [../threat-model.md](../threat-model.md) | What the agent can reach, and what an attacker would gain |
| [../controls.md](../controls.md) | How the run report maps checks to A.8.13 and other regulations |
| [../../SECURITY.md](../../SECURITY.md) | Vulnerability reporting and response targets |

## Control references

Control numbers and titles follow ISO/IEC 27001:2022 Annex A. The standard and its guidance in ISO/IEC 27002:2022 are copyrighted, so no control text is quoted.

## Current status

- **Segregation of duties (A.5.3) and independent code review (A.8.25, A.8.28):** the project has a single maintainer. Automated CI gates apply to every change.
- **Independent review (A.5.35):** no external security assessment or penetration test has been carried out yet.
