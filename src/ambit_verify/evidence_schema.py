# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Recorded credential-evidence versions shared by producer and verifier.

A supported historical version does not imply admission, holder proof or
freshness evidence that the original receipt did not retain.
"""

EVIDENCE_SCHEMA_VERSION = "6"
# v3/v4 retain historical credential meanings; v5 is the Phase-3
# authority-only execution profile. Only v6 carries Phase-4 consumption and
# resource-outcome evidence.
SUPPORTED_EVIDENCE_SCHEMA_VERSIONS = frozenset({"3", "4", "5", EVIDENCE_SCHEMA_VERSION})
