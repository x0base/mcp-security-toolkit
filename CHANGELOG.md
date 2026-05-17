# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] — security hardening, MCP-specific detectors, ecosystem features

Major release. Addresses findings from an external code/product audit,
expands the MCP-specific detector set, and ships the first ecosystem
features (defensive helpers library, SARIF output, GitHub Action, CLI
inventory scanner).

No breaking changes to the atomic-tool contract; new optional parameters
with safe defaults.

### Added — new MCP tool
- `interactsh_stop(token, delete_log=True)` — terminates a registered
  `interactsh-client` session and cleans up state.

### Added — `mcp_server_audit` detector pack
- 5 new AST detectors: `path-traversal` (D1),
  `tool-description-injection` (D2), `ssrf` (D3), `mcp-resource-uri-sqli`
  (D4), `tool-shadowing` (D5 cross-tool). `coverage.detectors_run` now
  lists all 13 active detector IDs. 9 fixture files + 9 pytest tests.
- `coverage` block (decorator-tools-found, imperative-tools-resolved,
  imperative-tools-external) and `limitations` list in every report —
  absence of finding is NOT proof of safety.

### Added — defensive helpers library (`mcp_security_toolkit.helpers`)
Drop-in primitives MCP authors can import to fix the bugs our detectors
flag. Pure functions, no I/O, no globals.
- `safe_path(user_path, root, must_exist=False)` — resolves and refuses
  traversal / symlink escape. Fixes `path-traversal`.
- `safe_url(url, allow_private=False)` — SSRF-safe URL validator with
  DNS resolution + private/loopback/metadata blocking. Fixes `ssrf`.
- `safe_sql_identifier(name, allow=None)` — table/column whitelist
  + strict regex. Fixes `mcp-resource-uri-sqli` and adjacent SQLi.

The toolkit is now on both sides of the bug: the detector finds it,
the helper fixes it in one line.

### Added — ecosystem features
- `mcp_security_toolkit.sarif.to_sarif(report)` — converts an
  `mcp_server_audit` report to SARIF 2.1.0 for GitHub Code Scanning.
- CLI: `mcp-security-toolkit scan-installed [--sarif]` — auto-discovers
  MCP servers in `~/.cursor/mcp.json`, `~/.claude/mcp.json`, and the
  Claude Desktop config on macOS / Windows, then audits any Python source
  referenced. Text or SARIF output. Non-zero exit on any `high` finding.
- CLI: `mcp-security-toolkit version`.
- `action.yml` — GitHub Action template. Composite action that installs
  the toolkit, runs the audit, emits SARIF, posts inline annotations,
  uploads to GitHub Code Scanning, and fails the build on configurable
  severity threshold.
- Default CLI behavior unchanged: invoking without subcommand still
  launches the MCP stdio server.

### Added — quality / hardening cross-cutting
- `jwt_inspect`: `weak_secret_check_performed` and
  `weak_secret_check_scope` fields make it explicit that the dictionary
  check is a smoke-test, not a strength proof.
- Dependabot config for GitHub Actions and pip ecosystems.

### Changed (security)
- `graphql_introspect`: response body capped at 5 MB to prevent OOM from
  a hostile target streaming unbounded data. Redirects are disabled in
  the underlying opener (any 3xx becomes an `HTTP-error: redirects
  disabled` error) — prevents post-preflight SSRF via Location header.
- `interactsh_register` / `interactsh_poll` / `interactsh_stop`: strict
  token regex (`^[a-f0-9]{12}$`) plus resolve-based boundary check on
  session paths and `log_path`. `_stop` and the TTL gc refuse to unlink
  anything outside the sessions dir.
- GitHub Actions pinned by full commit SHA (Dependabot will manage
  updates).
- `mcp_server_audit`: hard `max_bytes` limit on input (default 5 MB);
  files over the limit fail fast with `input-too-large` instead of
  blowing up `ast.parse` on pathological inputs.
- `graphql_introspect`: SSRF protection — blocks requests resolving to
  private, loopback, link-local, multicast, or cloud-metadata addresses
  by default. Opt in via `allow_private=True` to audit internal
  infrastructure. Timeout clamped to [1, 60] seconds.
- `interactsh_register`: session files written with 0600 perms (only
  the current user can read); sessions directory chmod 0700; old
  sessions auto-swept on each register (TTL 1h).
- `interactsh_poll`: caps log reads at 1 MB to bound memory.
- `phpggc_generate`: opt-in only — requires
  `MCP_SECURITY_TOOLKIT_ENABLE_OFFENSIVE=1` in the server's environment.
  Defensive default; the tool is for authorized testing.
- Runtime and dev deps now pinned with upper bounds (`<2.0` / `<9.0`
  etc.) to bound supply-chain surface.

## [0.2.0] — pentest pack

### Added
- `default_creds_lookup` — known default credentials by vendor/product.
- `sensitive_files_list` — curated sensitive paths per tech stack.
- `wordlist_gen` — OSINT-driven password / username / subdomain wordlists.
- `graphql_introspect` — GraphQL schema enumeration with security
  observations.
- `phpggc_generate` — wraps the `phpggc` CLI for PHP deserialization
  gadget chains.
- `interactsh_register` / `interactsh_poll` — wraps `interactsh-client`
  for OOB callback capture.

## [0.1.0] — LLM/agent security headline tools

### Added
- `mcp_server_audit` — AST-based source SAST for MCP server
  implementations.
- `agent_tool_risk_audit` — schema-level risk analysis for agent tools
  (OpenAI / Anthropic / MCP / bare JSON Schema).
- `prompt_injection_audit` — static review of system prompts and
  templates for prompt-injection surface.
- `owasp_llm_classify` — rule-based mapping of findings to OWASP LLM
  Top 10 (2025).
- `jwt_inspect` — JWT decode + audit (alg-none, weak HS-secret dictionary
  check, missing claims, suspicious `kid`, external key URLs).
- `http_diff` — security-flavored diff of two HTTP responses
  (auth-bypass / IDOR triage).
- Project scaffolding: `pyproject.toml`, FastMCP server, MIT license,
  pytest suite.
