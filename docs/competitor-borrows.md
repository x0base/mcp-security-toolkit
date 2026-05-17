# mcp-security-toolkit — competitive-borrow brief

**Audience:** dev-team agents (lead → scout → builder).
**Mission:** ship v0.5+ features that close gaps vs Snyk Agent Scan, MCPhound, Helixar Sentinel, sidhpurwala-huzaifa scanner. Keep static-analysis edge; add the table-stakes everyone else has; double-down on what makes us unique (PoC verification, defensive SDK).

**Not for revenue.** This product is x0base's developer-credibility flywheel feeding Redmai sales. Optimize for stars, mentions, "this scanner found a real CVE in our infra" testimonials.

---

## Competitive snapshot (2026-05-17)

| Competitor | Distinct feature we lack |
|---|---|
| **Snyk Agent Scan** (2,414⭐) | Inventory mode — scan ALL installed agent components on a machine (Claude Desktop / Cursor / VS Code configs, MCP servers, skills). Consent prompt before exec. |
| **Semgrep MCP** (666⭐) | Distribution — IDE deeplinks (LM Studio / Cursor / VS Code / Docker), uvx install, PyPI badges everywhere. |
| **MCPhound** | `npx` zero-install. Auto-detects all three host configs. Cross-server attack-path graph (NetworkX). 10 tool-poisoning regex. |
| **Helixar Sentinel** (8⭐) | SARIF output, GitHub Action, three scan modes (config / endpoint / container), fail-on threshold for CI gating. |
| **sidhpurwala-huzaifa** (21⭐) | Live HTTP/stdio scanning with auth checks. Includes deliberately-insecure test server as fixture. |
| **DMontgomery40** (12⭐) | Per-language specialization (JS/TS). Plugin architecture. |
| **AWS sample** (13⭐) | Wraps real SAST tools (Checkov + Semgrep + Bandit + ASH) — meta-scanner. |
| **MCPSafe / AgentAudit** (SaaS) | Public scoring badges. Auto-issue-filing on target repos. |

---

## Priority backlog — ordered by ROI

### P0 — table-stakes (3 weeks)

#### P0.1 — SARIF 2.1.0 output
**Source:** Helixar Sentinel.
**Why:** Industry-standard format. Enables GitHub Code Scanning integration → findings appear natively in PR UI. Without this, enterprises with security ops can't ingest us.
**Where:** new `src/mcp_security_toolkit/output/sarif.py`. Add `--format sarif` flag to `mcp_server_audit`.
**Acceptance:** SARIF output passes `sarif validate` against the 2.1.0 schema; loads in VS Code SARIF Viewer extension; loads in GitHub Code Scanning when uploaded via `codeql-action/upload-sarif`.
**Effort:** 2-3 days. Schema is well-documented. Use `sarif-om` Python library or hand-roll.

#### P0.2 — GitHub Action template
**Source:** Helixar Sentinel `action.yml`.
**Why:** Drop-in CI. Three required inputs (config / file / dir to scan), one output (SARIF), one fail-on threshold. After SARIF lands, action.yml is one day.
**Where:** new `.github/workflows/mcp-audit.yml` example + `action.yml` at repo root. Publish to `marketplace.github.com/actions/mcp-security-toolkit`.
**Acceptance:** A user with zero config can add 5 lines to their CI and start failing PRs on HIGH+ findings.
**Effort:** 1-2 days after SARIF.

#### P0.3 — `uvx mcp-security-toolkit` zero-install entrypoint
**Source:** MCPhound `npx` UX.
**Why:** Industry has shifted to zero-install dev experience. `pip install` is 2024.
**Where:** `pyproject.toml` `[project.scripts]` already has entry; verify `uvx mcp-security-toolkit audit <file>` works without manual install.
**Acceptance:** Single-line install + scan: `uvx mcp-security-toolkit audit ./server.py`.
**Effort:** Half day.

#### P0.4 — Inventory mode: `ov scan-installed`
**Source:** Snyk Agent Scan — its main differentiating mode.
**Why:** Most users have 5-20 MCP servers installed across Claude Desktop / Cursor / VS Code. They don't know where to point us. We should auto-detect.
**Where:** new `src/mcp_security_toolkit/inventory/` subpackage. Read these config paths:
- `~/.cursor/mcp.json`
- `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
- `~/.claude/claude_desktop_config.json`
- `~/.vscode/mcp.json` and workspace `.vscode/mcp.json`
- `~/.config/Code/User/settings.json` (extension entries)
Parse `mcpServers` block from each. For each entry: resolve the binary, run `mcp_server_audit` on its source if available, otherwise mark "external-only — can't inspect source".
**Acceptance:** `mcp-security-toolkit inventory` prints a table: server name → host → finding count → top severity.
**Effort:** 3-4 days.

### P1 — differentiators (4-6 weeks)

#### P1.1 — `pocgen` subcommand: auto-PoC engine
**Source:** Our own CVE hunt 2026-05-17 — we built PoCs by hand for 3 vulns and they were 10x more credible than the static finding.
**Why:** Nobody else does this. Every other scanner outputs "you have path traversal at line 42." We can output a runnable Python script that exploits it. This is **our killer differentiator** — pattern → verified PoC.
**Where:** new `src/mcp_security_toolkit/pocgen/` subpackage. Per-finding-category template engine. For `path-traversal`: emit a script that imports the tool, calls it with `/tmp/poc-evidence/outside-base.txt`, asserts file created. For `code-injection` / `eval`: emit a script that passes `__import__('os').system('id')`-style probe payload.
**Acceptance:** `mcp-security-toolkit pocgen --finding <id> --output poc.py` produces a runnable script. Run it; bug reproduces.
**Effort:** 1-2 weeks. Start with 3 categories (path-traversal, fs-destructive, code-injection); template the rest.

#### P1.2 — Defensive SDK: `mcp_security_toolkit.helpers`
**Source:** Reversal of the scanner pattern — no competitor offers this.
**Why:** Today every scanner says "you have path traversal." None of them ships a `from mcp_security_toolkit.helpers import safe_path` library that MCP authors can import to fix it in one line. We'd be **on both sides of the bug**.
**Where:** new `src/mcp_security_toolkit/helpers/` subpackage. Initial functions:

```python
# helpers/paths.py
def safe_path(user_path: str, root: str | Path) -> Path:
    """Resolve user_path inside root or raise. Single-line fix for path-traversal."""

def safe_filename(name: str) -> str:
    """Strip path separators and `..` from a filename. Returns basename only."""

# helpers/urls.py
def safe_url(user_url: str, *, allow_private: bool = False, allowed_schemes=("http","https")) -> str:
    """Resolve user_url, reject private/loopback/cloud-metadata unless allowed. SSRF-safe."""

# helpers/sql.py
def safe_identifier(name: str, *, allow=r"^[a-zA-Z_][a-zA-Z0-9_]*$") -> str:
    """Whitelist-validate a SQL identifier (table/column name). For when parameterization is impossible."""

# helpers/eval.py
def evaluate_expression(expr: str, *, variables: dict | None = None) -> Any:
    """Safe arithmetic-only evaluator. Use instead of eval() in tools that need formula input."""
```

**Marketing:** "Found path traversal? Replace `open(filename)` with `open(safe_path(filename, BASE_DIR))`. One line."
**Acceptance:** Each helper has positive tests (allowed inputs pass) and negative tests (attack payloads raise). Documented in README with before/after snippets.
**Effort:** 1 week for v1 with 4 helpers + tests + docs.

#### P1.3 — Tool-description-injection detector
**Source:** MCPhound (10 patterns); DVMP challenge 2 fixtures.
**Why:** Most prevalent MCP-specific bug class. We have it in spec/v0.4 already — make sure to ship with at least 10 regex patterns.
**Where:** v0.4 spec already covers; ensure parity with MCPhound's pattern set.

#### P1.4 — Cross-server attack-path analysis (lite)
**Source:** MCPhound's NetworkX graph approach. Their unique value.
**Why:** When user has filesystem-MCP + fetch-MCP + email-MCP installed together, the agent can read SSH keys (filesystem) and email them (email) — neither tool is bad alone, the combo is. Important for inventory mode (P0.4).
**Where:** new `src/mcp_security_toolkit/graph/` subpackage. After inventory scan, build a capability graph (read-fs, write-fs, http-fetch, exec, network-out, secret-store). Match against 5 starter attack chains:
1. **Data exfil:** read-fs + http-fetch
2. **Shell-via-data:** read-fs + git-write
3. **Credential theft:** secret-store-read + http-fetch
4. **Memory poisoning:** http-fetch + memory-write
5. **Backdoor install:** http-fetch + exec
**Acceptance:** `inventory --attack-paths` flag adds a "Combined risk" section to output listing matched chains. 5 chains in v0.5; add more in v0.6.
**Effort:** 1.5 weeks.

### P2 — credibility multipliers (ongoing)

#### P2.1 — Deliberately-vulnerable MCP server fixtures
**Source:** sidhpurwala-huzaifa scanner includes a test server. DVMP is a separate maintained corpus.
**Why:** "Our detector catches X. Try it: `git clone our-fixture; mcp-security-toolkit audit ./server.py`." Reproducible demos make claims credible.
**Where:** new `tests/fixtures/vulnerable-mcp-servers/` with 10 hand-crafted examples (one per detector category). README with `expected findings` per fixture.
**Acceptance:** Test fixture run produces exactly the documented findings (no false negatives in our own demos).
**Effort:** 3-4 days.

#### P2.2 — Public CVE write-up flywheel
**Source:** Our own cve-hunt work. Plus how Helixar / Lakera built reputation through paper publication.
**Why:** Each disclosed CVE → blog post → "found by mcp-security-toolkit" attribution → stars. Compounds.
**Where:** Markdown post in `docs/findings/` after each public CVE. Auto-update README "found CVEs" counter.
**Acceptance:** First CVE-id published with our attribution before end-of-quarter. Linked from README.

#### P2.3 — Mention parity with peer scanners
**Source:** All competitors have rich README distribution badges.
**Why:** Discovery via "MCP security scanner" GitHub search ranks by stars + readme richness. Match the table-stakes.
**Where:** Add to root README:
- LM Studio install deeplink (like Semgrep MCP has)
- Cursor / VS Code install deeplinks
- PyPI / Docker badges (we have PyPI Trusted Publishing — emphasize)
- Sigstore verification badge

### P3 — out of scope for v0.5/v0.6

- Public scoring service / registry (MCPSafe/AgentAudit territory; ethically questionable to auto-disclose).
- Discord community (MCPhound / Snyk territory; we prefer asynchronous GitHub Discussions).
- Multi-language (JS/TS) detectors (DMontgomery40 territory; stay Python-first for now).

---

## Sprint shape (suggested)

**Sprint A (week 1-2): table-stakes**
- P0.1 SARIF
- P0.2 GitHub Action
- P0.3 uvx entrypoint
- P0.4 Inventory mode (auto-detect host configs)

**Sprint B (week 3-4): defensive SDK + PoCgen**
- P1.2 helpers/{paths,urls,sql,eval}.py
- P1.1 pocgen for path-traversal first

**Sprint C (week 5-6): graph + fixtures + write-ups**
- P1.4 attack-path graph (lite)
- P2.1 vulnerable-mcp-server fixtures
- P2.2 first CVE write-up published

---

## Quality gates (must pass for every PR)

- `bun test` / `python -m pytest -q` — all green
- `ruff check src/ tests/` — clean
- `mypy src/` — clean
- New detector → ≥1 positive + ≥1 negative fixture
- New helper → ≥3 unit tests covering edge cases
- README change → links live, badges resolve

---

## Attribution table (when we copy)

| Concept | Source | License | Note |
|---|---|---|---|
| GitHub Action shape | Helixar Sentinel | Apache 2.0 | Reference architecture; rewrite for our schema |
| `npx`-style UX | MCPhound | MIT (presumed) | We use `uvx`, not `npx` — independent implementation |
| Inventory paths | Snyk Agent Scan | Apache 2.0 | List of config paths is fact, not creative work — no attribution needed |
| Tool-poisoning regex patterns | MCPhound | MIT (presumed) | Don't copy verbatim; write our own based on DVMP fixtures |
| Cross-server graph approach | MCPhound | MIT (presumed) | Concept is theirs; our impl + chain list is independent |

When in doubt: write our own implementation rather than copying. The patterns are the point — code is downstream.
