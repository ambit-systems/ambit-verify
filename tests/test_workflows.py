# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Supply-chain policy for executable GitHub workflow dependencies."""

from __future__ import annotations

import json
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
_UV_CHECKSUMS = {
    "ubuntu-latest": "440c4215b171e64061d65d16a23753dd25c29a7f7b1b0446c9e9aed0fa372f27",
    "macos-latest": "af171d5a4eb1c502819de32740aa811ff71851b1f5ec2d8bd0dda302ed9554c2",
}
_MATRIX_CHECKSUM = "${{ matrix.uv-checksum }}"
_MATRIX_ENTRY = re.compile(
    r'^ {10}- os: "([^"]+)"\n {12}uv-checksum: "([0-9a-f]{64})"$', re.MULTILINE
)


def _assert_installer_identities(content: str, *, matrix: bool) -> None:
    if matrix:
        platforms = re.search(r"^ {8}os: (\[[^\n]+\])$", content, re.MULTILINE)
        assert platforms is not None
        assert json.loads(platforms.group(1)) == list(_UV_CHECKSUMS)
        versions = re.search(r"^ {8}python-version: (\[[^\n]+\])$", content, re.MULTILINE)
        assert versions is not None
        assert json.loads(versions.group(1)) == ["3.14"]
        entries = _MATRIX_ENTRY.findall(content)
        assert len(entries) == len(_UV_CHECKSUMS)
        assert dict(entries) == _UV_CHECKSUMS
        expected = _MATRIX_CHECKSUM
    else:
        assert "runs-on: ubuntu-latest" in content
        expected = _UV_CHECKSUMS["ubuntu-latest"]
    blocks = _SETUP_UV.findall(content)
    assert blocks and len(blocks) == content.count("astral-sh/setup-uv@")
    for block in blocks:
        version = re.search(r'^\s+version:\s+"([^"]+)"$', block, re.MULTILINE)
        checksum = re.search(r'^\s+checksum:\s+"([^"]+)"$', block, re.MULTILINE)
        assert version is not None and version.group(1) == _UV_VERSION
        assert checksum is not None and checksum.group(1) == expected
        assert 'RUNNER_TOOL_CACHE: "${{ runner.temp }}/ambit-uv-tool-cache"' in block


@pytest.mark.parametrize("workflow", ["ci.yml", "release.yml"])
def test_external_workflow_actions_are_pinned_to_full_commit_shas(workflow: str) -> None:
    content = (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
    references = _USE.findall(content)

    assert references
    assert all(
        reference.startswith("./") or _FULL_SHA.fullmatch(reference) for reference in references
    )


def test_every_uv_installer_has_a_reviewed_platform_content_identity() -> None:
    for workflow in ("ci.yml", "release.yml"):
        content = (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
        _assert_installer_identities(content, matrix=workflow == "ci.yml")


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (_UV_CHECKSUMS["macos-latest"], _UV_CHECKSUMS["ubuntu-latest"]),
        (_UV_CHECKSUMS["ubuntu-latest"], _UV_CHECKSUMS["macos-latest"]),
        ("macos-latest", "windows-latest"),
        ('["3.14"]', '["3.13"]'),
        (_MATRIX_CHECKSUM, _UV_CHECKSUMS["ubuntu-latest"]),
        (_UV_VERSION, "0.9.11"),
        (_UV_CHECKSUMS["macos-latest"], ""),
    ],
)
def test_installer_policy_rejects_wrong_or_unpinned_identity(old: str, new: str) -> None:
    content = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    altered = content.replace(old, new)
    assert altered != content
    with pytest.raises(AssertionError):
        _assert_installer_identities(altered, matrix=True)


def test_installer_policy_rejects_missing_or_duplicate_platform_mapping() -> None:
    content = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    match = _MATRIX_ENTRY.search(content)
    assert match is not None
    entry = match.group()
    for replacement in ("", entry + "\n" + entry):
        with pytest.raises(AssertionError):
            _assert_installer_identities(content.replace(entry, replacement), matrix=True)


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
