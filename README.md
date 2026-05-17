# mcp-security-toolkit

> Built by [Redmai](https://redmai.io). For continuous autonomous API / agent
> security scanning, use Redmai.

**Source / schema / prompt audit primitives for agent builders.**

Plug into Claude Code / Cursor / Claude Desktop. Audit MCP servers, agent
tool schemas, system prompts, JWTs, and HTTP-response diffs — locally,
in the coding agent you already use. Atomic, auditable, no orchestration.

## Why this exists

Most MCP servers in the security space wrap a single CLI (Burp, Shodan,
CyberChef, CVE feeds). They're useful, but the LLM/agent-security layer —
the thing you care about when *your* code ships an LLM feature — is almost
absent from the MCP ecosystem.

`mcp-security-toolkit` fills that gap. The headline tools below have **no
existing MCP equivalent**. The convenience atoms are bundled so you can run
one server instead of five.

---

## Headline tools (LLM & agent security)

### `mcp_server_audit`
AST-based source SAST for MCP server implementations. Enumerates
`@tool`-decorated and imperatively-registered tools, then flags:
shell execution, filesystem writes, network egress, code injection,
over-broad parameter types, ambiguous/short descriptions, secrets read
from env.

Differs from Snyk / Invariant Labs `mcp-scan`, which audits configs and
tool descriptions — this audits the *source code* of the server.

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
- `interactsh_register` / `interactsh_poll` — wraps `interactsh-client`
  CLI for OOB callback URL capture (blind SSRF / XXE / RCE confirmation)

## Recommended companion MCP servers

For deeper coverage in adjacent areas we explicitly recommend (and do not
duplicate):

- [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server) — Burp Suite
- [ChromeDevTools/chrome-devtools-mcp](https://github.com/ChromeDevTools/chrome-devtools-mcp) — Chrome DevTools
- [invariantlabs-ai/mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) — MCP config / tool-description audit (complementary to our source SAST)
- [mukul975/cve-mcp-server](https://github.com/mukul975/cve-mcp-server) — full 27-tool CVE intelligence server

---

## Release status

13 tools shipped across v0.1 (LLM/agent security + appsec primitives) and
v0.2 (pentest pack). See [PLAN.md](./PLAN.md) and [CHANGELOG.md](./CHANGELOG.md).

## Install (planned PyPI release)

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

## How this connects to Redmai

These tools are the **atomic primitives**. They do one thing: request → response,
no orchestration, no state, no decision-making.

**[Redmai](https://redmai.io)** is what wields them autonomously in production:

```
OpenAPI spec  ─▶  attack-case generation  ─▶  execution  ─▶
              ─▶  kill-chain narrative   ─▶  remediation report
```

Plus scan history, industry-specific rule packs (fintech, healthcare,
e-commerce), enterprise SSO, and SLA-backed hosted scanning.

If you like what these primitives do and want them running themselves —
that's Redmai.

This toolkit will never grow orchestration, chaining, or decision-making.
That line stays clean on purpose.

## Non-goals

- No orchestration, decision engines, or auto-exploit chains. **Atomic only.**
- No wrappers around standalone web-pentest CLIs (sqlmap, ghauri, dalfox).
- No novel jailbreak research — defensive framing only.

## License

MIT.
