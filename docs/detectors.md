# v0.4 detectors — engineering brief

**Audience:** dev-team agents (lead → scout → builder cycle).
**Scope:** add four new detectors to `mcp_server_audit` covering MCP-specific bug classes that the current v0.3 implementation misses.
**Motivation:** during a 2026-05-17 CVE hunt, two confirmed path-traversal CVE-candidates (Office-Word-MCP-Server, Office-PowerPoint-MCP-Server, ~3,700 combined ⭐) were found, but neither was flagged by `mcp_server_audit` because we lack a path-traversal detector. The Damn Vulnerable MCP corpus (`harishsg993010/damn-vulnerable-MCP-server`) confirms gaps in three additional classes.

This brief defines the four detectors and the test fixtures that block merge.

---

## D1 — `path-traversal`

**Severity:** high (`severity: "high"`).
**Category string:** `path-traversal`.

### Heuristic

A `@tool`-registered function is flagged if **all three** hold:

1. **Parameter shape.** Function has at least one parameter whose name (lower-case) matches the regex `^(filename|file_path|filepath|path|output_path|output_filename|image_path|src_path|dst_path|source|destination|target|input_path|save_path)$`.
2. **Sink usage.** The function body uses that parameter (by name) as an argument to any of: `open(`, `Path(`, `pathlib.Path(`, `os.path.*(` (any), `Document(`, `Presentation(`, `shutil.copy*(`, `shutil.move(`, `shutil.rmtree(`, `subprocess.run(`, `subprocess.Popen(`, `os.makedirs(`, `os.remove(`, `os.unlink(`, `os.rename(`.
3. **Validation absence.** The function body does **NOT** contain any of: `.resolve()`, `.relative_to(`, `os.path.commonpath(`, `_path_is_inside(`, `is_safe_path(`, `secure_filename(`, an explicit reject of `..` in the parameter, or an explicit anchor against a configured root constant (heuristic: appearance of any UPPER_CASE name matching `^[A-Z_]+(ROOT|DIR|BASE|HOME)$` adjacent to the parameter).

### Implementation hint

Walk the function's AST. Build a set of `target_params` from parameter names matching the regex. For each `ast.Call` in the body, check whether any arg ASTs reference a `target_param` (by `ast.Name` id). Also collect the set of method names called on those params. Apply rule 3 as a negation check on the function body's calls.

### Rationale

This is the highest-value detector — it would have caught both Office-Word-MCP-Server and Office-PowerPoint-MCP-Server in the recent hunt.

### Test fixtures

- **Positive:** `damn-vulnerable-MCP-server/challenges/easy/challenge3/server.py` (`read_file` tool).
- **Positive:** `damn-vulnerable-MCP-server/challenges/medium/challenge6/server.py` (`upload_and_process_document`).
- **Negative:** `mcp-security-toolkit/src/mcp_security_toolkit/tools/interactsh.py` (`interactsh_poll` — has `_path_is_inside` check, must NOT flag).

---

## D2 — `tool-description-injection`

**Severity:** medium (`severity: "medium"`).
**Category string:** `tool-description-injection`.

### Heuristic

A `@tool`-registered function is flagged if its docstring contains **any** of:

1. **HTML/XML-style injection tags**, case-insensitive: `<IMPORTANT>`, `<SYSTEM>`, `<ADMIN>`, `<URGENT>`, `<SECRET>`, `<INSTRUCTION>`, `<HIDDEN>`, `<DO_NOT_DISPLAY>`.
2. **Imperative override phrases**, case-insensitive (full-word match):
   - `IGNORE PREVIOUS`
   - `DISREGARD INSTRUCTIONS`
   - `DO NOT MENTION`
   - `DO NOT TELL`
   - `ALWAYS INCLUDE`
   - `ALWAYS USE`
   - `MUST ACCESS`
   - `BEFORE RESPONDING`
   - `PRETEND`
3. **Cross-resource invocation markers**: docstring claims another resource/tool must be silently fetched (regex `access(?:ing)?\s+(?:the\s+)?resource\s+at|silently\s+(?:fetch|read|call)`).

### Implementation hint

Walk AST for `FunctionDef` nodes with `@tool` decorators. Grab `ast.get_docstring(node)`. Run the patterns. Emit a single finding per matched tool with a `matches` array.

### Rationale

DVMP challenge 2 is the canonical example: hidden `<IMPORTANT>` block telling the LLM to fetch a "confidential" resource silently. This is the classic "tool poisoning" pattern called out by OWASP LLM Top 10 (LLM06: Sensitive Information Disclosure / LLM08: Excessive Agency).

### Test fixtures

- **Positive:** `damn-vulnerable-MCP-server/challenges/easy/challenge2/server.py` (`get_company_data` — `<IMPORTANT>` block).
- **Negative:** any of our own tools (`graphql_introspect`, `jwt_inspect`, etc.).

---

## D3 — `ssrf`

**Severity:** high (`severity: "high"`).
**Category string:** `ssrf`.

### Heuristic

A `@tool`-registered function is flagged if **all** hold:

1. **Parameter shape.** Has at least one parameter named `url`, `uri`, `endpoint`, `target_url`, `webhook_url`, `callback_url`, `link`, `host`, `target`.
2. **Sink usage.** Function body passes that parameter to any of: `urllib.request.urlopen(`, `urlopen(`, `requests.get(`, `requests.post(`, `requests.put(`, `requests.delete(`, `requests.request(`, `httpx.get(`, `httpx.post(`, `httpx.AsyncClient(`, `aiohttp.ClientSession(`.
3. **Validation absence.** Function body does NOT contain any of: `_is_private_address(`, `ipaddress.ip_address(`, `is_global`, host-allowlist check (heuristic: `in ALLOWED_` constant or `host in `), scheme allow-list check that rejects `file://` / `gopher://` / `ftp://` (heuristic: a comparison like `scheme not in ('http', 'https')` or `startswith('http')`).

### Implementation hint

Mirror D1's AST walk. We already implemented the validation pattern in `graphql_introspect.py` (`_is_private_address`) — use that as the "good shape" reference.

### Test fixtures

- **Positive:** craft a minimal fixture in `tests/fixtures/ssrf_positive.py` — a tool that takes `url` and passes to `requests.get(url)` with no guard.
- **Negative:** `mcp-security-toolkit/src/mcp_security_toolkit/tools/graphql_introspect.py` (has the preflight).

---

## D4 — `mcp-resource-uri-sqli`

**Severity:** high (`severity: "high"`).
**Category string:** `mcp-resource-uri-sqli`.

### Heuristic

For each function decorated with `@app.read_resource`, `@server.read_resource`, `@mcp.resource(...)`, or `@app.resource(...)`:

1. Track variables assigned from `<param>.split(`, `<param>[N:]`, `<param>.removeprefix(`, `urlparse(<param>)` where `<param>` is a function arg (typically `uri`).
2. If any such derived variable is interpolated into an f-string or `.format()` that becomes an argument to `.execute(`, `.executemany(`, `.execute_many(`, `cursor.execute*(`, `conn.execute(`, `engine.execute(`, flag.

### Rationale

`designcomputer/mysql_mcp_server`'s `read_resource` pattern. Not in DVMP, so we'll add a minimal fixture.

### Test fixtures

- **Positive:** add `tests/fixtures/mcp_uri_sqli.py` modeling the mysql_mcp_server pattern. (Do NOT use the real mysql_mcp_server source — it's a private pre-disclosure target.)
- **Negative:** any resource handler that uses parameterized queries.

---

## Cross-cutting requirements

### File locations
- All four detectors live in `src/mcp_security_toolkit/tools/mcp_server_audit.py`, registered the same way as existing detectors (`_analyze_function` and `_collect_file_level_findings`).
- Test fixtures in `tests/fixtures/v0_4/`.
- Tests in `tests/test_mcp_server_audit.py` (extend, do not split into a new file).

### Coverage block
The `Coverage` model gets a new field `detectors_run: list[str]` enumerating which detectors actually executed. Update `limitations` text to reference the new detectors.

### CLI / API surface
No breaking changes. Detectors are always on. Future enhancement (out of scope): `--rules` flag to enable/disable individual detectors.

### Configurability
None for v0.4. Hardcoded patterns. We tune them based on real findings during the next hunt batch.

### CHANGELOG / version
- Bump `pyproject.toml` and `__init__.py` to `0.4.0`.
- CHANGELOG section `## [0.4.0] — MCP-specific detectors`.

### Quality gates (must pass before merge)
- `bun test` (we use pytest, but CLAUDE.md convention) → `python -m pytest -q`
- `ruff check src/ tests/`
- `mypy src/`
- ≥1 positive + ≥1 negative fixture per detector with assertions.

### Acceptance criteria
- Running v0.4 against `damn-vulnerable-MCP-server` flags **at least** challenges 2 (`tool-description-injection`), 3 (`path-traversal`), 6 (`path-traversal`), 9 (`shell-exec`, already covered).
- Running v0.4 against the v0.3 self-tests does NOT produce regressions (existing fixture expectations still hold).
- README updated to list the new detectors in the "What we catch" section.

---

## Out of scope for v0.4

- SARIF export.
- GitHub Actions workflow template.
- `--rules` enable/disable flag.
- AST recursion-limit hardening (already shipped in v0.3).
- Detector autofix suggestions.

These go into a v0.5 backlog.

---

## Branch / PR plan

Suggested split (one PR per detector keeps review tractable):

1. `feat/d1-path-traversal` — implementation + tests + fixtures.
2. `feat/d2-tool-description-injection` — same.
3. `feat/d3-ssrf` — same.
4. `feat/d4-mcp-resource-uri-sqli` — same.
5. `chore/v0.4-release` — version bump, CHANGELOG, README, docs/v0.4-detectors-spec.md → mark spec as DONE.

Each PR small enough to review in 15 minutes. Each generates one Pull Shark increment.
