# Copyright (c) 2026 Ambit Systems Pty Ltd. All rights reserved.
# Proprietary and confidential. See LICENSE for terms.

"""No identifier belonging to Ambit Systems the company reaches the product.

Ambit Authority and Ambit Observatory are generic agent authority products. A
customer names their own repositories, hosts, branches and paths, so none of
ours may appear in what ships or in what a customer reads to deploy it. Ambit
running its own development under Ambit contributes mechanism to the product;
its policy belongs in an authority entry, never in this repository.

Constitution section 7, hard rule 9.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# What a customer receives and copies. `README.md`, `.github/` and `scripts/`
# are our own clone and build instructions, which name our organisation because
# they must. `docs/` cross-links to the documentation repository by design, a
# deliberate pattern rather than leakage; whether a customer can follow those
# links is a documentation decision, not a product one.
SCANNED = ("src", "deploy")
SKIP = {
    ".git",
    ".venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
}
SUFFIXES = {".py", ".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".cfg"}
MAX_BYTES = 2_000_000

MARKERS: dict[str, re.Pattern[str]] = {
    "company GitHub organisation": re.compile(r"github\.com[:/]ambit-systems"),
    "company domain": re.compile(r"ambit-systems\.com"),
    "company repository": re.compile(
        r"\bambit-(?:os|docs|demos|labs|business|outreach|website|playbook|press"
        r"|memex|harness|constitution|operating-model|logos|console)\b(?!-api)"
    ),
    "absolute home path": re.compile(r"/Users/|/home/[a-z]"),
    "company branch namespace": re.compile(r"refs/heads/agent/"),
    "self-developing programme": re.compile(r"self-develop", re.IGNORECASE),
}

# Each entry is one known violation kept only until it is extracted, with the
# reason it survives. A violation that is fixed must be deleted from here: an
# unused entry fails this test, so the list can only shrink.
ALLOWED: dict[tuple[str, str], str] = {}


def _found() -> set[tuple[str, str]]:
    """Return every (path, marker) pair present in the shipped source."""
    hits: set[tuple[str, str]] = set()
    for name in SCANNED:
        target = ROOT / name
        if not target.exists():
            continue
        candidates = [target] if target.is_file() else sorted(target.rglob("*"))
        for path in candidates:
            if not path.is_file() or path.suffix not in SUFFIXES:
                continue
            if SKIP & set(path.relative_to(ROOT).parts):
                continue
            if path.stat().st_size > MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for marker, pattern in MARKERS.items():
                if pattern.search(text):
                    hits.add((path.relative_to(ROOT).as_posix(), marker))
    return hits


def test_no_company_identifier_reaches_the_product() -> None:
    unexpected = sorted(_found() - set(ALLOWED))
    assert not unexpected, (
        "company-specific content in the product source: "
        + "; ".join(f"{path} carries a {marker}" for path, marker in unexpected)
        + ". Move it to an authority entry or a company repository."
    )


def test_the_allowlist_only_shrinks() -> None:
    stale = sorted(set(ALLOWED) - _found())
    assert not stale, (
        "allowlisted violations that no longer exist: "
        + "; ".join(f"{path} / {marker}" for path, marker in stale)
        + ". Delete them from ALLOWED."
    )
