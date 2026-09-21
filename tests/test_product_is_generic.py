# Copyright (c) 2026 Ambit Systems Pty Ltd. All rights reserved.
# Proprietary and confidential. See LICENSE for terms.

"""The product carries no identifier belonging to Ambit Systems the company.

Ambit Authority and Ambit Observatory are generic agent authority products. A
customer names their own repositories, hosts, branches and paths, so none of
ours may be compiled into what ships. Ambit running its own development under
Ambit contributes mechanism to the product; its policy belongs in an authority
entry, never in this source tree.
"""

from __future__ import annotations

import re
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "src"
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
ALLOWED: dict[tuple[str, str], str] = {
    ("ambit_verify/resource_protocol.py", "company branch namespace"): (
        "The public verifier requires our own agent branch namespace, so a "
        "customer publishing elsewhere cannot verify a valid receipt. The "
        "constraint belongs in the authority entry, checked against the receipt."
    ),
}


def _found() -> set[tuple[str, str]]:
    """Return every (path, marker) pair present in the shipped source."""
    hits: set[tuple[str, str]] = set()
    for path in sorted(SOURCE.rglob("*")):
        if path.suffix not in SUFFIXES or not path.is_file():
            continue
        if path.stat().st_size > MAX_BYTES:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for marker, pattern in MARKERS.items():
            if pattern.search(text):
                hits.add((path.relative_to(SOURCE).as_posix(), marker))
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
