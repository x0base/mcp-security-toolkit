"""OSINT-driven wordlist generator.

Given a target's surface info (brand, names, year, location, keywords),
returns a deduplicated wordlist of plausible usernames / passwords /
subdomain labels suitable for authorized credential or directory testing.

Pure function. No network. Atomic.
"""

from __future__ import annotations

from itertools import product
from typing import Literal

from pydantic import BaseModel

LEET_MAP = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}
SUFFIXES = ["", "1", "12", "123", "1234", "!", "!1", "2023", "2024", "2025", "2026"]
SEPARATORS = ["", ".", "_", "-"]


class GenReport(BaseModel):
    mode: str
    total: int
    sample: list[str]
    truncated: bool


def _leet(word: str) -> str:
    return "".join(LEET_MAP.get(c, c) for c in word)


def _capitalize_variants(word: str) -> set[str]:
    return {word.lower(), word.upper(), word.capitalize(), word.title()}


def _passwords(seeds: list[str], years: list[str]) -> set[str]:
    out: set[str] = set()
    for s in seeds:
        if not s:
            continue
        base = s.lower()
        out.update(_capitalize_variants(base))
        out.add(_leet(base))
        out.add(_leet(base).capitalize())
        for suf in SUFFIXES + years:
            if not suf:
                continue
            out.add(base + suf)
            out.add(base.capitalize() + suf)
            out.add(_leet(base) + suf)
    return out


def _usernames(names: list[str], brand: str | None) -> set[str]:
    out: set[str] = set()
    for n in names:
        n = n.strip().lower()
        if not n:
            continue
        parts = n.split()
        if len(parts) == 1:
            out.add(parts[0])
            continue
        first, *_, last = parts
        out.add(f"{first}")
        out.add(f"{last}")
        out.add(f"{first}.{last}")
        out.add(f"{first[0]}{last}")
        out.add(f"{first}{last[0]}")
        out.add(f"{first}_{last}")
        out.add(f"{last}.{first}")
        out.add(f"{last}{first[0]}")
        if brand:
            out.add(f"{first}.{last}@{brand.lower()}")
    return out


def _subdomains(brand: str, keywords: list[str]) -> set[str]:
    out: set[str] = set()
    base = brand.lower()
    common = [
        "dev", "stage", "staging", "test", "qa", "uat", "preprod", "beta",
        "internal", "intranet", "vpn", "mail", "smtp", "imap", "owa", "exchange",
        "api", "admin", "portal", "auth", "sso", "git", "gitlab", "github",
        "jenkins", "ci", "cd", "k8s", "prom", "grafana", "kibana", "splunk",
        "old", "new", "backup", "bak", "legacy", "demo", "sandbox", "lab",
    ]
    out.update(common)
    for kw in keywords:
        kw = kw.strip().lower()
        if not kw:
            continue
        out.add(kw)
        for sep, suf in product(SEPARATORS, common):
            out.add(f"{kw}{sep}{suf}")
    for suf in common:
        out.add(f"{base}-{suf}")
        out.add(f"{suf}-{base}")
    return out


def wordlist_gen(
    mode: Literal["passwords", "usernames", "subdomains"],
    brand: str | None = None,
    names: list[str] | None = None,
    keywords: list[str] | None = None,
    years: list[str] | None = None,
    max_size: int = 5000,
) -> dict:
    """Generate a wordlist tailored to the target surface.

    Modes:
      - `passwords`: combine brand / keyword seeds with leet substitution,
        capitalization variants, common suffixes and year suffixes.
      - `usernames`: combine person names into common patterns
        (`first`, `last`, `first.last`, `flast`, `firstl`, …).
      - `subdomains`: combine brand + keywords with a curated list of
        common environment / service subdomain labels.

    Pure function. No network.

    Args:
        mode: One of `passwords`, `usernames`, `subdomains`.
        brand: Target organization brand (used in all modes).
        names: List of person names ("Jane Doe") for `usernames` mode.
        keywords: Additional seed words for `passwords` / `subdomains`.
        years: Year strings to append (passwords mode).
        max_size: Hard cap on returned entries.

    Returns:
        GenReport with `sample` (the wordlist itself, up to `max_size`).
    """
    if mode not in ("passwords", "usernames", "subdomains"):
        return {"error": f"mode must be passwords|usernames|subdomains, got {mode!r}"}

    seeds: list[str] = []
    if brand:
        seeds.append(brand)
    if keywords:
        seeds.extend(keywords)

    if mode == "passwords":
        out = _passwords(seeds, years or [])
    elif mode == "usernames":
        if not names:
            return {"error": "usernames mode requires `names`"}
        out = _usernames(names, brand)
    else:
        if not brand:
            return {"error": "subdomains mode requires `brand`"}
        out = _subdomains(brand, keywords or [])

    sorted_out = sorted({w for w in out if w})
    truncated = len(sorted_out) > max_size
    return GenReport(
        mode=mode,
        total=len(sorted_out),
        sample=sorted_out[:max_size],
        truncated=truncated,
    ).model_dump()
