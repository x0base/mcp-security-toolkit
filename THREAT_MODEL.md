# Threat Model

What this toolkit protects, what it doesn't, and how it should be deployed.

## Users

- **Primary:** AppSec / AI-Security engineers conducting authorized review
  inside Claude Code / Cursor / Claude Desktop.
- **Secondary:** developers building LLM applications who want pre-flight
  audits on their own MCP servers, agent tools, and prompts.

## Trust boundaries

The toolkit runs **on the user's local machine** as an MCP stdio server.
It trusts:
- the local user
- the inputs the user (or their agent) passes to each tool
- the local Python environment

It does **not** trust:
- targets of any audit (target source files, JSON schemas, prompt strings,
  HTTP responses are treated as untrusted data)
- external HTTP endpoints (`graphql_introspect`) — failures and odd
  responses are caught
- wrapped external CLIs (`phpggc`, `interactsh-client`) — failures are
  surfaced, not blindly executed

## In-scope risks (we defend against these)

- **Arbitrary code execution from analyzed input.** All audit tools are
  static. They `ast.parse` and walk source trees but never `exec`/`eval`
  user-supplied code.
- **Path traversal in audit inputs.** Tools that take a file path
  (`mcp_server_audit`) read but never write; they do not follow symlinks
  beyond the user-supplied path's normal resolution.
- **DoS via pathological input.** Regex and AST walks are bounded by input
  size; long inputs hit reasonable timeouts and truncation in network calls.

## Tool outputs are untrusted data

Several tools return content that originated from an attacker-controlled
source: `http_diff` includes excerpts from target response bodies,
`interactsh_poll` returns raw OOB requests, `graphql_introspect` returns
target-controlled type and field names, and any audit tool may quote text
from the file or schema it inspected.

These payloads will end up inside the agent's context window. If they
contain text like *"ignore previous instructions and ..."* the agent
itself may follow them — this is **indirect prompt injection**, and it
is a property of LLM agents in general, not of this toolkit.

**Guidance for MCP clients:**
- Treat any string field inside a tool's JSON response as untrusted data.
- Render tool output to the user inside a fenced block or with clear
  delimiters (e.g. an `<tool_output>` XML tag) so the model has a
  syntactic signal that the content is data, not instructions.
- Do not silently flow tool output into a subsequent prompt as if it
  were part of the system role.
- For AppSec workflows, prefer reviewing tool output yourself before
  re-prompting the agent with summaries.

The toolkit will not sanitize these strings because we cannot
distinguish data from instruction inside an arbitrary text blob without
hurting legitimate use (auditing a prompt that *describes* an attack).
This is a responsibility that lives in the client / orchestrator.

## Out-of-scope risks (we don't defend against these)

- **Misuse by an authorized user against unauthorized targets.** This
  toolkit will happily generate a wordlist or run a GraphQL introspection
  against any URL. Authorization is the caller's responsibility.
- **Malicious MCP clients.** If a hostile MCP client passes crafted JSON
  to our tools, the worst it can achieve is to make us produce a useless
  report. We do not write files, we do not execute commands derived from
  audited inputs.
- **Compromised wrapped binaries.** If a user installs a backdoored
  `phpggc` or `interactsh-client`, that is outside our trust boundary.
- **LLM hallucination.** This toolkit gives an agent factual primitives.
  How the agent interprets them is the agent's concern.

## Explicit non-goals

- **No orchestration / decision-making across tools.** That is by design.
  Orchestration belongs in [Redmai](https://redmai.io). Adding it here
  would create a new threat surface (autonomous action with no human in
  the loop) that this design refuses.
- **No novel offensive research.** All techniques referenced here are
  publicly documented (citations in each tool that needs them). We will
  not accept PRs that bundle non-public attack techniques.
- **No state across tool calls.** No findings DB, no scan history, no
  cross-call memory. The toolkit is amnesiac on purpose.

## Deployment guidance

- Run as a local stdio MCP server. Do not expose over a network.
- Treat outputs as advisory — they are static heuristics, not verdicts.
- For continuous / fleet-wide / autonomous scanning, use Redmai instead;
  that product is designed for it.

## Reporting

See [SECURITY.md](./SECURITY.md).
