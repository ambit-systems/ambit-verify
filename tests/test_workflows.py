# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Supply-chain policy for executable GitHub workflow dependencies."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_USE = re.compile(r"^\s*(?:-\s+)?uses:\s+([^#\s]+)", re.MULTILINE)
_FULL_SHA = re.compile(r"^[^@]+@[0-9a-f]{40}$")
_SETUP_UV = re.compile(
    r"^\s{6}-\s+uses:\s+astral-sh/setup-uv@[^\n]+(?:\n(?!\s{6}-\s).*)*",
    re.MULTILINE,
)
_UV_VERSION = "0.9.10"
_UV_CHECKSUM = "440c4215b171e64061d65d16a23753dd25c29a7f7b1b0446c9e9aed0fa372f27"


@pytest.mark.parametrize("workflow", ["ci.yml", "release.yml"])
def test_external_workflow_actions_are_pinned_to_full_commit_shas(workflow: str) -> None:
    content = (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
    references = _USE.findall(content)

    assert references
    assert all(
        reference.startswith("./") or _FULL_SHA.fullmatch(reference) for reference in references
    )


def test_every_uv_installer_has_one_reviewed_content_identity() -> None:
    identities: set[tuple[str, str]] = set()
    for workflow in ("ci.yml", "release.yml"):
        content = (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
        blocks = _SETUP_UV.findall(content)
        assert len(blocks) == content.count("astral-sh/setup-uv@")
        for block in blocks:
            version = re.search(r'^\s+version:\s+"([^"]+)"$', block, re.MULTILINE)
            checksum = re.search(r'^\s+checksum:\s+"([0-9a-f]{64})"$', block, re.MULTILINE)
            assert version is not None
            assert checksum is not None
            identities.add((version.group(1), checksum.group(1)))
            assert 'RUNNER_TOOL_CACHE: "${{ runner.temp }}/ambit-uv-tool-cache"' in block

    assert identities == {(_UV_VERSION, _UV_CHECKSUM)}


def test_release_build_uses_the_locked_backend_environment() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert pyproject["build-system"]["requires"] == ["hatchling==1.27.0"]
    assert 'name = "hatchling"\nversion = "1.27.0"' in lock
    assert "uv sync --group build --locked --no-install-project" in release
    assert "uv build --no-build-isolation" in release


def test_package_platform_metadata_matches_the_supported_smoke_matrix() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    classifiers = set(pyproject["project"]["classifiers"])
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "Operating System :: OS Independent" not in classifiers
    assert {
        "Operating System :: MacOS",
        "Operating System :: POSIX :: Linux",
    } <= classifiers
    assert "runs-on: ${{ matrix.os }}" in ci
    assert 'os: ["ubuntu-latest", "macos-latest"]' in ci
    assert "/ambit-verify samples/five-receipts/evidence.jsonl" in ci
