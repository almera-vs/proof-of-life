# Statement of applicability, for this product

Which ISO/IEC 27001:2022 Annex A controls are relevant to Proof of Life as a product, and where each is addressed. **This is an input to your own statement of applicability, not a replacement for it.** Controls about people, buildings and your wider organisation remain yours, and are marked "Organisation".

Legend:
- **D**: development of the product, see `development-controls.md`.
- **P**: a control the product helps you operate, see `product-controls.md`.
- **Organisation**: outside the product.
- **Not applicable**: the product has no bearing on it.

## A.5 Organisational controls
| Control | Applies | Where |
|---|---|---|
| 5.1 Policies for information security | Organisation | Your ISMS. The product contributes `secure-development-policy.md` |
| 5.2 Information security roles and responsibilities | Organisation | Owners named in `risk-register.md` |
| 5.3 Segregation of duties | D | Single maintainer; CI gates on every change |
| 5.4 Management responsibilities | Organisation | |
| 5.5 Contact with authorities | Organisation | |
| 5.6 Contact with special interest groups | Organisation | |
| 5.7 Threat intelligence | D | Vulnerability feeds through govulncheck, CodeQL and Dependabot |
| 5.8 Information security in project management | D | |
| 5.9 Inventory of information and other associated assets | D | SBOM per release |
| 5.10 Acceptable use of information and other associated assets | Organisation | |
| 5.11 Return of assets | Organisation | |
| 5.12 Classification of information | Organisation | Classify reports and evidence under your scheme |
| 5.13 Labelling of information | Organisation | |
| 5.14 Information transfer | P | Only results leave, to the targets you configure |
| 5.15 Access control | P | Read-only role, owner-only key |
| 5.16 Identity management | Organisation | |
| 5.17 Authentication information | P | Secrets by reference only, redacted in output |
| 5.18 Access rights | Organisation | |
| 5.19 Information security in supplier relationships | Organisation | Proof of Life is itself a supplier to you |
| 5.20 Addressing information security within supplier agreements | Organisation | |
| 5.21 Managing information security in the ICT supply chain | D | |
| 5.22 Monitoring, review and change management of supplier services | Organisation | |
| 5.23 Information security for use of cloud services | Organisation | Backup storage is yours |
| 5.24 Information security incident management planning and preparation | D | `SECURITY.md` for the product. Your incidents are yours |
| 5.25 Assessment and decision on information security events | Organisation | |
| 5.26 Response to information security incidents | Organisation | Failed drills are signals; see `operations.md` |
| 5.27 Learning from information security incidents | Organisation | |
| 5.28 Collection of evidence | P | Signed evidence log |
| 5.29 Information security during disruption | P | |
| 5.30 ICT readiness for business continuity | P | Core purpose |
| 5.31 Legal, statutory, regulatory and contractual requirements | P | DORA, NIS2 and SOC 2 mapping in `docs/controls.md` |
| 5.32 Intellectual property rights | D | |
| 5.33 Protection of records | P | |
| 5.34 Privacy and protection of PII | P | |
| 5.35 Independent review of information security | D | No external assessment yet |
| 5.36 Compliance with policies, rules and standards for information security | D | Enforced in CI |
| 5.37 Documented operating procedures | P | `docs/operations.md` |

## A.6 People controls
6.1 to 6.8 (screening, terms of employment, awareness, disciplinary process, responsibilities after termination, confidentiality agreements, remote working, event reporting): **Organisation.** The product has no bearing on them.

## A.7 Physical controls
7.1 to 7.14: **Organisation.** The product runs on infrastructure you provide.

## A.8 Technological controls
| Control | Applies | Where |
|---|---|---|
| 8.1 User endpoint devices | Not applicable | |
| 8.2 Privileged access rights | P | |
| 8.3 Information access restriction | P | |
| 8.4 Access to source code | D | |
| 8.5 Secure authentication | P | Database TLS verification flagged by `pol validate` |
| 8.6 Capacity management | P | Sizing in `operations.md` |
| 8.7 Protection against malware | D | Release checksums and provenance. Distroless image |
| 8.8 Management of technical vulnerabilities | D | |
| 8.9 Configuration management | D, P | |
| 8.10 Information deletion | P | |
| 8.11 Data masking | P | Not provided; see `product-controls.md` |
| 8.12 Data leakage prevention | P | |
| 8.13 Information backup | P | Core purpose |
| 8.14 Redundancy of information processing facilities | Organisation | |
| 8.15 Logging | P | |
| 8.16 Monitoring activities | P | |
| 8.17 Clock synchronization | P | Relies on host NTP |
| 8.18 Use of privileged utility programs | P | The agent needs the Docker socket; see `risk-register.md` R2 |
| 8.19 Installation of software on operational systems | D | Verifiable releases |
| 8.20 Networks security | P | |
| 8.21 Security of network services | Organisation | |
| 8.22 Segregation of networks | P | |
| 8.23 Web filtering | Not applicable | |
| 8.24 Use of cryptography | P | |
| 8.25 Secure development life cycle | D | |
| 8.26 Application security requirements | D | |
| 8.27 Secure system architecture and engineering principles | D | |
| 8.28 Secure coding | D | |
| 8.29 Security testing in development and acceptance | D | |
| 8.30 Outsourced development | D | No outsourced development |
| 8.31 Separation of development, test and production environments | D, P | |
| 8.32 Change management | D | |
| 8.33 Test information | D | |
| 8.34 Protection of information systems during audit testing | P | |
