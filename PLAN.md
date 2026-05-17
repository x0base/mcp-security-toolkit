# Plan

## Positioning

**Source / schema / prompt audit primitives for agent builders.**
One install. Headline tools fill the LLM/agent-security gap in MCP today.
Pentest pack ships everyday primitives so an agent has the basics without
chasing five separate MCP servers.

## v0.1 — LLM/agent security headline (all shipped)

These are the reason the toolkit exists. Lead with these in README, demo,
and launch posts. Each has no existing MCP equivalent (or only a partial
overlap).

| Tool | Status | Notes |
|---|---|---|
| `mcp_server_audit` | ✅ shipped | Heuristic AST source-audit for MCP server implementations. Differentiator vs Snyk / Invariant Labs `mcp-scan`, which scans configs/descriptions — we scan the source. |
| `agent_tool_risk_audit` | ✅ shipped | Schema-level risk analysis for an agent tool definition (OpenAI / Anthropic / MCP / bare JSON Schema). |
| `prompt_injection_audit` | ✅ shipped | Static review of a system prompt for injection surface. Garak / PyRIT / Promptfoo exist as CLIs but none ship as an MCP tool. |
| `owasp_llm_classify` | ✅ shipped | Rule-based mapping of a finding to OWASP LLM Top 10 (2025). |
| `jwt_inspect` | ✅ shipped | JWT decode + audit (`alg:none`, weak HS-secret dictionary check, missing claims, suspicious `kid`, external key URLs). |
| `http_diff` | ✅ shipped | Security-flavored diff of two HTTP responses (auth-bypass / IDOR triage). |

## v0.2 — pentest pack (all shipped)

Atomic primitives for authorized AppSec / pentest workflows.

| Tool | Status | Group | Notes |
|---|---|---|---|
| `default_creds_lookup` | ✅ shipped | Intel | 50+ vendor/product defaults, aliases (`fortigate`, `idrac`, `wp`). |
| `sensitive_files_list` | ✅ shipped | Recon | Paths-only per stack (`common`, `php`, `wordpress`, `dotnet`, `java`, `node`, `python`, `k8s`, `docker`, `ci`); does not probe. |
| `wordlist_gen` | ✅ shipped | Payloads | `passwords` / `usernames` / `subdomains` modes. |
| `graphql_introspect` | ✅ shipped | Recon | Single introspection POST → schema summary + security observations. |
| `phpggc_generate` | ✅ shipped | Payloads | Wraps `phpggc` CLI; graceful if binary missing. |
| `interactsh_register` | ✅ shipped | OOB | Wraps `interactsh-client` CLI; spawns detached, returns callback URL + token. |
| `interactsh_poll` | ✅ shipped | OOB | Reads captured DNS/HTTP/SMTP interactions for a token. |

## Explicitly NOT shipping

Strong official servers exist — duplicating dilutes the brand. README lists
them as recommended companions.

- Burp tools → use **PortSwigger/mcp-server**
- Chrome DevTools → use **ChromeDevTools/chrome-devtools-mcp**
- Full MCP config / tool-description audit → use **invariantlabs-ai/mcp-scan**
  (complementary to our source-level audit)
- Full 27-tool CVE intelligence → use **mukul975/cve-mcp-server**

## v0.3 — backlog

Candidate additions, ordered by demand signal we expect:

- `secrets_in_context` — PII / secret detector across a transcript or
  conversation history.
- `llm_threat_model` — STRIDE-like threat-model template generator for
  an LLM application description.
- Extend `mcp_server_audit` with TypeScript / Node MCP support.
- Extend `owasp_llm_classify` rule weights based on community-submitted
  observations.
- `cve_lookup` thin atomic version (NVD + EPSS + KEV in one call) —
  only if upstream `mukul975/cve-mcp-server` proves too heavy for users.

## The atomic-only rule (Redmai boundary)

**Atomic only. No orchestration, no chaining, no decision-making across tools.
If a feature requires the toolkit to decide what to do next, it belongs in
[Redmai](https://redmai.io), not here.**

| | mcp-security-toolkit | Redmai |
|---|---|---|
| Paradigm | Atomic request → response | Autonomous end-to-end |
| Caller decides next step? | Yes (agent / human) | No (system decides) |
| State across calls? | No | Yes |
| What it ships | Primitives | A product |

This rule is the single test for every new tool. The toolkit is a screwdriver
drawer; Redmai is the factory.

Concrete lines that stay uncrossed:
- No orchestration / pipelines / decision engines
- No auto-exploit chains
- No state layer (findings DB, evidence store, cross-call memory)
- No wrappers around full standalone web-pentest CLIs (sqlmap, ghauri, dalfox, …)
- No infra/ops tooling (VPS, GPU, domain registrars)
- No novel jailbreak research — defensive framing only

## Cross-cutting release work

| Item | Status |
|---|---|
| SECURITY.md | ✅ |
| THREAT_MODEL.md | ✅ |
| CONTRIBUTING.md | ✅ |
| CHANGELOG.md | ✅ |
| MIT LICENSE | ✅ |
| `.gitignore` | ✅ |
| GitHub Actions CI (ruff + pytest, 3.10–3.13, ubuntu + macos) | ✅ |
| `git init` + first commit | pending |
| GitHub repo creation | pending |
| 2-minute demo video | pending |
| PyPI release | pending |
