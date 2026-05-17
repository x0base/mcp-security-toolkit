# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
