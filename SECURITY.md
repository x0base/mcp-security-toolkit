# Security Policy

## Supported versions

Only the latest minor version receives security fixes. Pre-1.0 releases may
ship breaking changes alongside fixes.

| Version | Supported |
|---|---|
| 0.x     | ✅ |
| < 0.1   | ❌ |

## Reporting a vulnerability

Please report vulnerabilities **privately** — do not open a public issue.

- Email: `security@redmai.io`
- Preferred: PGP-encrypted message (key on request)
- Subject line: `[mcp-security-toolkit] <short summary>`

Include:
1. Affected version / commit
2. Reproduction steps or proof-of-concept
3. Impact you observe
4. Any suggested mitigation

We aim to acknowledge within **3 business days** and provide a remediation
plan within **14 days** for confirmed issues.

## Scope

In scope:
- Vulnerabilities in this repository's source code
- Vulnerabilities exposed when running `mcp-security-toolkit` as an MCP server
- Vulnerabilities in dependencies that we pin or ship

Out of scope:
- Issues in tools we wrap but do not ship (`phpggc`, `interactsh-client`) —
  report those to their respective maintainers
- Vulnerabilities in target systems that callers of this toolkit choose to
  audit
- Use of this toolkit against systems without authorization

## Responsible use

This toolkit is intended for authorized security testing, defensive review,
and education. Running these tools against systems you do not own or have
explicit permission to test may violate computer-fraud laws in your
jurisdiction. See [THREAT_MODEL.md](./THREAT_MODEL.md) for the design
boundaries.

## Hall of fame

Researchers credited for valid reports will be listed here (with consent).
