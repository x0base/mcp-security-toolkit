"""Wrap the `phpggc` CLI to generate a PHP deserialization gadget chain.

Atomic: chain name + command + options → serialized payload string.
Does not deliver, fire, or stage the payload.

Requires `phpggc` installed and on PATH:
  https://github.com/ambionics/phpggc

For authorized testing only.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Literal

from pydantic import BaseModel

OPT_IN_ENV = "MCP_SECURITY_TOOLKIT_ENABLE_OFFENSIVE"

ENCODINGS = ("raw", "base64", "url", "json", "soft")


class PhpggcReport(BaseModel):
    available: bool
    chain: str | None
    encoding: str
    payload: str | None = None
    stderr: str | None = None
    cmd: list[str] = []


def phpggc_generate(
    chain: str,
    command: str,
    encoding: Literal["raw", "base64", "url", "json", "soft"] = "base64",
    fast_destruct: bool = False,
    extra_args: list[str] | None = None,
) -> dict:
    """Generate a single PHP unserialize gadget chain via `phpggc`.

    Args:
        chain: Gadget chain identifier (e.g. `Laravel/RCE9`, `Symfony/RCE4`,
            `Monolog/RCE1`). Run `phpggc -l` locally to enumerate.
        command: Shell command to embed in the chain (e.g. `id`, `curl ...`).
        encoding: One of `raw`, `base64`, `url`, `json`, `soft`.
        fast_destruct: Adds `--fast-destruct` (triggers without await).
        extra_args: Extra raw arguments to pass through.

    Returns:
        PhpggcReport with the generated payload (string). If `phpggc` is not
        installed, `available` is False.
    """
    if os.environ.get(OPT_IN_ENV, "").lower() not in {"1", "true", "yes"}:
        return {
            "error": "offensive-tool-disabled",
            "hint": (
                f"This tool generates PHP deserialization payloads and is "
                f"disabled by default. Set {OPT_IN_ENV}=1 in the MCP server's "
                f"environment to enable. Only use against systems you are "
                f"explicitly authorized to test."
            ),
        }

    if not isinstance(chain, str) or not chain.strip():
        return {"error": "chain must be a non-empty string"}
    if not isinstance(command, str) or not command.strip():
        return {"error": "command must be a non-empty string"}
    if encoding not in ENCODINGS:
        return {"error": f"encoding must be one of {ENCODINGS}"}

    bin_path = shutil.which("phpggc")
    if not bin_path:
        return PhpggcReport(
            available=False, chain=chain, encoding=encoding,
            stderr="phpggc binary not found on PATH — install from https://github.com/ambionics/phpggc",
        ).model_dump()

    args: list[str] = [bin_path]
    if encoding == "base64":
        args.append("-b")
    elif encoding == "url":
        args.append("-u")
    elif encoding == "json":
        args.append("-j")
    elif encoding == "soft":
        args.append("-s")
    # encoding == "raw" → no flag
    if fast_destruct:
        args.append("--fast-destruct")
    if extra_args:
        args.extend(str(a) for a in extra_args)
    # `--` separates flags from positional args: prevents a `chain` value
    # starting with `-` from being reinterpreted as a phpggc flag.
    args.append("--")
    args.extend([chain, command])

    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=30, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return PhpggcReport(
            available=True, chain=chain, encoding=encoding,
            stderr=f"phpggc execution failed: {e}", cmd=args,
        ).model_dump()

    if result.returncode != 0:
        return PhpggcReport(
            available=True, chain=chain, encoding=encoding,
            stderr=result.stderr.strip() or "non-zero exit", cmd=args,
        ).model_dump()

    return PhpggcReport(
        available=True, chain=chain, encoding=encoding,
        payload=result.stdout.strip(), cmd=args,
    ).model_dump()
