# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | Yes       |

## Scope

This policy covers security vulnerabilities in the `signet-exporter` binary and its dependencies as distributed from this repository. It does not cover vulnerabilities in the host operating system or infrastructure configuration.

## Reporting a Vulnerability

**Do not file a public GitHub issue for security vulnerabilities.**

Please report security vulnerabilities via email to:

**security@maravexa.io**

Include in your report:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (if applicable)
- The version(s) of `signet-exporter` affected
- Any suggested mitigations

### What to Expect

| Timeline | Action |
|----------|--------|
| 48 hours | Acknowledgement of your report |
| 7 days | Initial assessment and severity classification |
| 30 days | Target for patch release (critical/high severity) |
| 90 days | Coordinated public disclosure |

We follow responsible disclosure. If you need to share a large proof-of-concept, request a PGP key in your initial email.

## Out of Scope

- Vulnerabilities requiring physical access to the host
- Denial-of-service attacks against the `/metrics` endpoint from already-authorized scrapers
- Issues in the IEEE OUI database content (third-party data)
- Vulnerabilities in container orchestration platforms or Kubernetes configurations not provided in this repository
