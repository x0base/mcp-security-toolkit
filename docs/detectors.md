# `mcp_server_audit` — detector reference

Per-detector heuristic, severity, rationale, and fixture references for
every rule that `mcp_server_audit` runs against a Python MCP server's
source. SARIF reports emitted by the audit link here via `helpUri`
(`docs/detectors.md#<rule-id>`).

All detectors below are part of `coverage.detectors_run`. Heuristic
SAST — false negatives are expected. Absence of a finding is NOT proof
of safety; see the `limitations` block in every report.

The MCP-specific detectors (path-traversal, tool-description-injection,
ssrf, mcp-resource-uri-sqli, tool-shadowing) shipped in **v0.3.0**.
They were introduced after a 2026-05-17 CVE hunt found two
path-traversal CVE candidates in popular MCP servers (Office-Word and
Office-PowerPoint MCP servers, ~3,700 combined ⭐) that the earlier
generic detector set did not catch.

---

## shell-exec

**Severity:** high

Flags calls into `subprocess.{run,call,Popen,check_output,check_call}`,
`os.{system,popen,exec*,spawn*}` from inside a `@tool`-registered
function. Tracks `from subprocess import run [as r]` aliases so renamed
dangerous imports don't slip through.

**Fix:** never accept a shell command from an agent. If you must run
an external process, build the `args` list yourself (no `shell=True`)
and validate every value against an allow-list.

---

## fs-write / fs-destructive

**Severity:** medium (`fs-write`) / high (`fs-destructive`)

`fs-write` fires when a `@tool` function opens a file with a write
mode (`'w'`, `'a'`, `'x'`). `fs-destructive` fires on
`shutil.rmtree` / `os.remove` / `os.unlink`.

**Fix:** wrap the path in `safe_path(name, root=...)` from
`mcp_security_toolkit.helpers` so writes/deletes are constrained to a
directory the tool owns.

---

## network-egress

**Severity:** medium

Flags outbound HTTP calls via `requests.{get,post,request}`,
`httpx.{get,post}`, `urllib.request.urlopen` from inside a `@tool`.

**Fix:** if the destination is user-controlled, validate via
`safe_url(url)` (blocks private / loopback / metadata addresses by
default) before fetching.

---

## code-injection

**Severity:** high

Flags `eval()`, `exec()`, `compile()` inside a `@tool`. Almost always
a critical bug when the argument is derived from agent input.

**Fix:** for arithmetic / formula input, use
`evaluate_expression(expr, variables=...)` from
`mcp_security_toolkit.helpers`. For anything else, parse your own
DSL — never `eval`.

---

## over-broad-param

**Severity:** medium

Flags a `@tool` parameter whose name suggests a path / command / URL
but whose annotation is a bare type (`str`, `dict`, `list`, `Any`,
`object`) with no validator or `Literal` constraint. The agent will
pass anything; the tool will accept anything.

**Fix:** add `Literal["..."]` or a Pydantic model with `pattern` /
`enum`; or validate inside the tool using the relevant `helpers.safe_*`
function.

---

## ambiguous-description

**Severity:** low–medium

Fires when a `@tool` has no docstring (medium) or a docstring shorter
than 40 chars (low). An LLM relies on the docstring to decide when to
call the tool; a missing / vague one is a misuse vector.

**Fix:** write a one-paragraph docstring that states what the tool
does, what inputs it accepts, and what it returns.

---

## secret-in-env

**Severity:** info

Module-level finding. Flags `os.getenv("…KEY…" / "…TOKEN…" /
"…SECRET…" / "…PASSWORD…")` so the audit report doubles as a
secret-handling inventory.

**Fix:** documentation only — make sure secret-bearing env vars are
named, documented in your README, never echoed in logs, and never
returned from tool output.

---

## path-traversal

**Severity:** high

Flags a `@tool`-registered function when **all three** hold:

1. **Parameter shape.** At least one parameter whose name matches
   `^(filename|file_path|filepath|path|output_path|output_filename|image_path|src_path|dst_path|source|destination|target|input_path|save_path)$`
2. **Use shape.** The parameter is passed to `Path()` / `open()` /
   `os.path.join` and the result reaches a side-effecting call
   (`.write_text`, `.read_text`, `open(..., 'w'/'a'/'x')`,
   `shutil.copy*`, `os.makedirs`).
3. **No sanitization in the same function.** No call to
   `safe_path` / `safe_filename` / `Path.resolve().relative_to(...)` /
   `Path.is_relative_to(...)` / `os.path.commonpath` between the
   parameter and its use.

**Fix:** import `safe_path` (or `safe_filename` if the parameter is a
filename joined to a fixed root inside the tool) and apply it as the
first statement of the tool function.

**Fixtures:** `tests/fixtures/v0_4/path_traversal_positive.py`,
`tests/fixtures/v0_4/path_traversal_negative.py`.

---

## tool-description-injection

**Severity:** medium

Flags a `@tool` whose docstring contains text that looks like an
instruction to a model rather than documentation: phrases like *"ignore
previous instructions"*, *"you are now…"*, *"system:"*, *"<|im_start|>"*,
imperative second-person commands directed at the model
(*"as the assistant, you must…"*).

A docstring is in the model's context window whenever the tool is
exposed. Hostile docstrings (e.g. from a third-party MCP server an
agent imports) are an indirect prompt-injection vector.

**Fix:** keep docstrings descriptive, not imperative-to-the-model.
Describe what the tool does and its arguments. If you must include
literal text that would otherwise trigger this, quote it in code
fences and clarify intent.

**Fixture:** `tests/fixtures/v0_4/tool_desc_injection_positive.py`.

---

## ssrf

**Severity:** high

Flags a `@tool` when **both** hold:

1. A parameter whose name suggests a URL / endpoint / host
   (`url`, `endpoint`, `target`, `host`, `webhook`, `callback`, `uri`).
2. The parameter is passed to an outbound HTTP call
   (`requests.*`, `httpx.*`, `urllib.request.urlopen`, `aiohttp.*`)
   without `safe_url` / equivalent allow-list / private-IP check
   between parameter and call.

**Fix:** wrap with `safe_url(url, allow_private=False)` (blocks
private / loopback / link-local / metadata addresses by default).

**Fixtures:** `tests/fixtures/v0_4/ssrf_positive.py`,
`tests/fixtures/v0_4/ssrf_negative.py`.

---

## mcp-resource-uri-sqli

**Severity:** high

Flags `@read_resource`-decorated handlers (and equivalents) that
unpack a URI's path components and interpolate one of them into an
SQL string. The MCP `@read_resource("db://{table}/{id}")` pattern
makes URI components feel like trusted "routes," but they're agent
input — interpolating into SQL is classic injection.

**Fix:** use `safe_sql_identifier(name, allow={...})` for table /
column names that **must** be interpolated; use parameterized queries
(`cursor.execute(sql, (value,))`) for values.

**Fixtures:** `tests/fixtures/v0_4/mcp_uri_sqli_positive.py`,
`tests/fixtures/v0_4/mcp_uri_sqli_negative.py`.

---

## tool-shadowing (cross-tool, file-level)

**Severity:** medium

Module-level finding. Fires when two `@tool`-registered functions in
the same server have very similar names (edit-distance ratio ≥ 0.8)
or very similar docstrings. LLMs are sensitive to small wording
differences — two near-duplicate tools mean the model may invoke
whichever one the agent thinks is right, possibly the wrong one.

**Fix:** rename one tool to make the distinction load-bearing; or
collapse the two into a single tool with a `mode` parameter.

**Fixture:** `tests/fixtures/v0_4/tool_shadowing_positive.py`.

---

## Reading a SARIF report from `mcp_server_audit`

Each finding's `ruleId` corresponds to a section above. Severity
maps to SARIF `level`:

| Audit severity | SARIF level |
|---|---|
| high | `error` |
| medium | `warning` |
| low / info | `note` |

`mcp_security_toolkit.sarif.to_sarif(report)` emits SARIF 2.1.0.
Upload via `github/codeql-action/upload-sarif` to populate the
Security tab.
