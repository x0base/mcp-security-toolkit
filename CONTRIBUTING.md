# Contributing

Thanks for considering a contribution. A few rules keep this toolkit small,
focused, and defensible.

## The atomic-only rule

Every tool in this repo follows one rule:

> Atomic only. One input → one output. No orchestration, no chaining,
> no decision-making across tools. If a feature needs the toolkit to
> decide what to do next, it belongs in [Redmai](https://redmai.io),
> not here.

PRs that introduce pipelines, schedulers, decision engines, or stateful
flows will be closed.

## Adding a new tool

1. **Open an issue first** describing the tool: input, output, why it
   belongs here (not in Redmai), and whether an existing MCP server
   already does it. We won't merge "yet another wrapper" — see
   `README.md` for the companion servers we recommend instead.
2. Create `src/mcp_security_toolkit/tools/<name>.py`. Keep it under
   ~400 lines.
3. The public function must:
   - Be a pure function (no I/O beyond what the tool itself does).
   - Accept primitive arguments (`str`, `dict`, `int`, `list`, `bool`).
   - Return a `dict` (use Pydantic models internally and `.model_dump()`).
   - Have a docstring that names inputs, outputs, and what the tool does
     *and* what it does not do.
4. Add tests in `tests/test_<name>.py`. Cover input validation, edge
   cases, and at least one realistic-shape input. No network in unit
   tests — mock or use fixtures.
5. Register the tool in `src/mcp_security_toolkit/server.py`.
6. Update `README.md` and `PLAN.md` to list the new tool.
7. Add an entry to `CHANGELOG.md` under `## Unreleased`.

## Adding a defender tool that wraps a CLI

Wrap, don't reimplement. Provide:
- a `shutil.which` check, returning `{"available": False, "error": ...}`
  if the binary is missing,
- a hard subprocess timeout,
- structured stdout/stderr separation,
- no shell=True.

## Style

- Python ≥ 3.10. Use modern syntax (`X | Y`, `list[str]`, walrus where it
  helps).
- Format / lint with `ruff` (`pyproject.toml` is the source of truth).
- Type hints required on public functions.
- Comments only where the *why* is non-obvious. Don't narrate the *what*.

## Running the test suite

```
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/ruff check .
```

## Defensive framing

This is a defensive-leaning toolkit:
- We do not accept novel attack techniques. Cite a public source for any
  technique you reference (paper, OWASP entry, vendor advisory).
- Tools that generate offensive payloads (`phpggc_generate`, etc.) wrap
  an existing public utility — do not reimplement.
- For each tool, include a one-line note in the docstring on the
  authorization assumption.

## License

By contributing, you agree your contribution is licensed under MIT
(see `LICENSE`).
