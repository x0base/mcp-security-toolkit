# mcp-security-toolkit

[![CI](https://github.com/x0base/mcp-security-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/x0base/mcp-security-toolkit/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mcp-security-toolkit.svg)](https://pypi.org/project/mcp-security-toolkit/)
[![Python](https://img.shields.io/pypi/pyversions/mcp-security-toolkit.svg)](https://pypi.org/project/mcp-security-toolkit/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> Built by [Redmai](https://redmai.io). For continuous autonomous API / agent
> security scanning, use Redmai.

**Source / schema / prompt audit primitives for agent builders.**

Plug into Claude Code / Cursor / Claude Desktop. Audit MCP servers, agent
tool schemas, system prompts, JWTs, and HTTP-response diffs — locally,
in the coding agent you already use. Atomic, auditable, no orchestration.

## Why this exists

Most security-flavored MCP servers wrap an existing CLI (Burp, Shodan,
CyberChef) or audit MCP configurations and tool descriptions. The primitives
a developer reaches for when *their own* code ships an LLM feature —
source-level audit of an MCP server, schema-level audit of an agent tool,
static review of a system prompt — are thinly covered.

`mcp-security-toolkit` ships those primitives, plus the everyday pentest
atoms an agent reaches for during AppSec work, so you can run one server
instead of five.

---

## Headline tools

### `mcp_server_audit`
Heuristic AST audit of an MCP server's Python source. Enumerates
`@tool`-decorated and imperatively-registered tools, then runs 13 detectors:

| Detector | Category | Sev |
|---|---|---|
| Shell execution | `shell-exec` | high |
| Filesystem write/delete | `fs-write` / `fs-destructive` | med–high |
| Network egress | `network-egress` | medium |
| Code injection | `code-injection` | high |
| Over-broad params | `over-broad-param` | medium |
| Ambiguous/missing docstring | `ambiguous-description` | low–med |
| Secret read from env | `secret-in-env` | info |
| **Path traversal** (v0.4) | `path-traversal` | high |
| **Prompt injection in docstring** (v0.4) | `tool-description-injection` | medium |
| **SSRF via URL param** (v0.4) | `ssrf` | high |
| **Resource URI → SQL injection** (v0.4) | `mcp-resource-uri-sqli` | high |
| **Tool shadowing** (v0.4) | `tool-shadowing` | medium |

Tracks `from X import Y [as Z]` aliases so renamed dangerous imports
don't slip through. Reports include a `coverage.detectors_run` list and
`limitations` — absence of finding is NOT proof of safety.

Complements Snyk / Invariant Labs `mcp-scan`, which audits MCP configs
and tool descriptions — this audits the *source code* of the server.

### `agent_tool_risk_audit`
Takes a single agent tool's JSON schema and reports schema-level risks:
over-broad params, ambiguous descriptions, missing constraints, exfil
potential, dangerous defaults.

### `prompt_injection_audit`
Static review of a system prompt / template for injection surface.
Flags untrusted placeholders, missing delimiters, trust-boundary
violations, dangerous-instruction patterns.

### `owasp_llm_classify`
Map a finding or observation to OWASP LLM Top 10 (2025) with reasoning
and severity. Useful in reports and ticket creation.

### `http_diff`
Appsec-focused diff of two HTTP responses. For manual auth-bypass / IDOR
triage. Highlights set/added/removed headers, status changes, body diffs,
and security-relevant cookies.

### `jwt_inspect`
Decode + audit a JWT. Flags `alg:none`, weak HS-secrets (small dictionary
check), expiry, missing standard claims, suspicious `kid` (path traversal),
external key URLs (`jku`, `x5u`).

---

## Pentest pack (atomic primitives)

Bundled so an agent has the basics without needing five MCP installs. Each
tool is one input → one output, no chaining.

- `default_creds_lookup` — known default credentials by vendor / product
  (50+ products, aliases like `fortigate`, `idrac`, `wp`)
- `sensitive_files_list` — curated sensitive paths per tech stack
  (`common`, `php`, `wordpress`, `dotnet`, `java`, `node`, `python`,
  `k8s`, `docker`, `ci`); returns paths only, does not probe
- `wordlist_gen` — OSINT-driven wordlist generator
  (`passwords` / `usernames` / `subdomains` modes)
- `graphql_introspect` — single introspection POST → schema summary +
  security observations
- `phpggc_generate` — wraps `phpggc` CLI for PHP-deserialization gadget
  chains (graceful if binary missing)
- `interactsh_register` / `interactsh_poll` / `interactsh_stop` —
  wraps `interactsh-client` CLI for OOB callback URL capture (blind SSRF /
  XXE / RCE confirmation). `_stop` terminates and cleans up the session;
  TTL gc runs on every register

## Example output

Real output from three of the headline tools. Click to expand.

<details>
<summary><b><code>mcp_server_audit</code></b> on a deliberately-bad fixture — finds <code>subprocess.run</code> shell-exec, over-broad <code>path: str</code> params, missing docstring, fs-write, and a secret read from env.</summary>

```json
{
  "file": "sample_mcp_server.py",
  "tools_found": 4,
  "summary": {"high": 1, "medium": 5, "low": 1, "info": 1},
  "tools": [
    { "name": "safe_echo", "findings": [] },
    {
      "name": "run_cmd",
      "findings": [
        {"category": "ambiguous-description", "severity": "low",
         "message": "docstring is very short (4 chars) — risk of LLM misuse"},
        {"category": "over-broad-param", "severity": "medium",
         "message": "parameter `cmd`: command-like parameter typed as bare `str`"},
        {"category": "shell-exec", "severity": "high",
         "message": "calls `subprocess.run`"}
      ]
    },
    {
      "name": "read_anything",
      "findings": [
        {"category": "ambiguous-description", "severity": "medium",
         "message": "tool has no docstring — the LLM cannot reason about when to use it"},
        {"category": "over-broad-param", "severity": "medium",
         "message": "parameter `path`: path-like parameter typed as bare `str` (no allow-list)"}
      ]
    },
    {
      "name": "write_log",
      "findings": [
        {"category": "over-broad-param", "severity": "medium",
         "message": "parameter `path`: path-like parameter typed as bare `str` (no allow-list)"},
        {"category": "fs-write", "severity": "medium",
         "message": "opens file for writing (mode='a')"}
      ]
    }
  ],
  "file_level_findings": [
    {"category": "secret-in-env", "severity": "info",
     "message": "reads secret from env `SECRET_API_KEY` — ensure it is documented in README and never logged"}
  ]
}
```
</details>

<details>
<summary><b><code>agent_tool_risk_audit</code></b> on a tool schema with bare-string <code>cmd</code> / <code>url</code>, a URL+data exfil shape, and <code>verify_ssl: false</code>.</summary>

```json
{
  "tool_name": "shell_exec",
  "detected_format": "mcp",
  "findings": [
    {"category": "ambiguous-description", "severity": "medium", "path": "<tool>",
     "message": "description is very short (5 chars) — high risk of LLM misuse"},
    {"category": "risky-name-vague-desc", "severity": "medium", "path": "<tool>",
     "message": "tool name suggests it executes ('exec') but description is brief — agent may misuse"},
    {"category": "over-broad-param", "severity": "high", "path": "cmd",
     "message": "command-like param `cmd` is bare string — agent can execute arbitrary commands"},
    {"category": "over-broad-param", "severity": "high", "path": "url",
     "message": "url-like param `url` is bare string with no `pattern` — agent can reach arbitrary hosts (SSRF / exfil)"},
    {"category": "dangerous-default", "severity": "medium", "path": "verify_ssl",
     "message": "safety-related param `verify_ssl` defaults to `False` — disables a safeguard by default"},
    {"category": "exfil-shape", "severity": "medium", "path": "<tool>",
     "message": "tool accepts both a URL-like destination and a data-like payload — classic exfil shape"}
  ]
}
```
</details>

<details>
<summary><b><code>jwt_inspect</code></b> on the well-known <code>jwt.io</code> default token — verifies signature against a small weak-secret dictionary, finds missing claims.</summary>

```json
{
  "valid_structure": true,
  "header": {"alg": "HS256", "typ": "JWT"},
  "payload": {"sub": "1234567890", "name": "John Doe", "iat": 1516239022},
  "weak_secret": "your-256-bit-secret",
  "findings": [
    {"category": "missing-claim", "severity": "medium",
     "message": "no `exp` claim — token never expires"},
    {"category": "missing-claim", "severity": "low", "message": "no `iss` claim"},
    {"category": "missing-claim", "severity": "low", "message": "no `aud` claim"},
    {"category": "weak-secret", "severity": "high",
     "message": "signature verifies with common weak secret: 'your-256-bit-secret'"}
  ]
}
```
</details>

## Recommended companion MCP servers

For deeper coverage in adjacent areas we explicitly recommend (and do not
duplicate):

- [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server) — Burp Suite
- [ChromeDevTools/chrome-devtools-mcp](https://github.com/ChromeDevTools/chrome-devtools-mcp) — Chrome DevTools
- [invariantlabs-ai/mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) — MCP config / tool-description audit (complementary to our source-level audit)
- [mukul975/cve-mcp-server](https://github.com/mukul975/cve-mcp-server) — full 27-tool CVE intelligence server

---

## Install

```bash
pip install mcp-security-toolkit
```

```json
{
  "mcpServers": {
    "sec": { "command": "mcp-security-toolkit" }
  }
}
```

## Developing locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check .
```

End-to-end MCP smoke test (boots the server over stdio, lists tools,
calls two of them):

```bash
python scripts/smoke_mcp.py
```

## Defensive helpers — fix what we detect

The tools above **find** unsafe patterns in MCP servers. The
[`mcp_security_toolkit.helpers`](./src/mcp_security_toolkit/helpers/)
package is the inverse: drop-in primitives an MCP author imports to make
their tools safe by construction.

```python
from mcp_security_toolkit.helpers import safe_path, safe_url, safe_sql_identifier

@mcp.tool()
def read_log(name: str) -> str:
    p = safe_path(name, root="/var/log/myapp", must_exist=True)
    return p.read_text()

@mcp.tool()
def fetch_url(url: str) -> str:
    url = safe_url(url)                                    # blocks SSRF
    return httpx.get(url, timeout=5).text

ALLOWED_TABLES = {"users", "orders", "events"}

@mcp.tool()
def count_rows(table: str) -> int:
    table = safe_sql_identifier(table, allow=ALLOWED_TABLES)
    return db.execute(f"SELECT COUNT(*) FROM {table}").scalar()
```

Pure functions, no I/O, no globals. Each fixes the corresponding
`mcp_server_audit` finding category in one line.

## GitHub Action

Drop into any repo to run `mcp_server_audit` in CI, upload SARIF to the
Security tab, and fail the build on configured severity:

```yaml
# .github/workflows/mcp-audit.yml
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v5
      - uses: x0base/mcp-security-toolkit@v0.3
        with:
          path: src/my_mcp_server.py
          fail-on-severity: high
```

## CLI

```bash
# Default (no args): start the MCP stdio server — what your client config invokes
mcp-security-toolkit

# Audit every MCP server your local Claude / Cursor / Claude Desktop is configured to launch
mcp-security-toolkit scan-installed
mcp-security-toolkit scan-installed --sarif > findings.sarif

# Zero-install run, via uv
uvx mcp-security-toolkit scan-installed
```

## Treat tool outputs as untrusted data

Some tools return content from attacker-controlled sources: `http_diff`
quotes target response bodies, `interactsh_poll` returns raw OOB requests,
`graphql_introspect` returns target-controlled schema names. If such a
string contains *"ignore previous instructions..."*, an LLM agent reading
it may follow the embedded instruction — classic indirect prompt
injection. MCP clients should render tool outputs inside delimiters
(`<tool_output>...`) and not flow them silently into the next prompt.
See [THREAT_MODEL.md](./THREAT_MODEL.md#tool-outputs-are-untrusted-data).

## Non-goals

- No orchestration, chaining, or decision logic across tools — primitives only.
- No reimplementation of full-featured offensive CLIs (`sqlmap`, `ghauri`,
  `dalfox`); where wrapping a small, focused CLI is a natural fit
  (`phpggc`, `interactsh-client`), we wrap it directly with a graceful
  "binary not found" path.
- No novel offensive research — all referenced techniques cite public sources.

## License

MIT.
