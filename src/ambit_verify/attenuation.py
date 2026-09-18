# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Attenuation: whether a child delegation narrows its parent, and on which axis.

One rule set, applied at mint time so a widening request never reaches a
signer, and at verification time so a chain minted elsewhere meets the same
rule. ``attenuation_rule_hash()`` binds this exact rule body into every
ratification, so a reader can tell which rule approved a grant.
"""

from __future__ import annotations

import inspect
import io
import os.path as _osp
import textwrap
import tokenize
from collections.abc import Callable
from datetime import datetime
from typing import Any

from .hashing import canonical_json_bytes, sha256_hex
from .models import DelegationClaims

# Bumped whenever an axis is added, removed, or renamed. It is a label a
# maintainer can forget, which is why every ratification also binds
# ``attenuation_rule_hash()`` -- a hash of the rule's own source.
ATTENUATION_RULE_VERSION = "5"

# Every axis :func:`_scope_widening_axis` can name, in the order it checks them.
# A test pins this table against the function's own returns, so an axis added
# without a version bump fails the build.
AXES: tuple[str, ...] = (
    "actions",
    "paths",
    "capabilities",
    "time",
    "named_set",
    "bounds",
    "applies_to",
    "aggregate_bound",
    "quorum",
    "tools",
    "domains",
    "lineage",
    "aud",
    "revocation_age",
    "max_depth",
)


def _grant_windows(claims: DelegationClaims, action: str) -> list[tuple[datetime, datetime]]:
    """Every ``(nbf, exp)`` window during which *claims* authorises *action*.

    Flat slip (no capabilities): the single slip window when the action is in ``scope_actions``,
    else ``[]``. Structured slip: one window per capability containing the action (the capabilities
    are the effective grant; an action absent from every capability is NOT granted, even if it
    appears in ``scope_actions``) — this is what stops a child from reintroducing an action the
    parent's structured grant omitted.
    """
    if not claims.capabilities:
        return [(claims.nbf, claims.exp)] if action in set(claims.scope_actions) else []
    return [(cap.nbf, cap.exp) for cap in claims.capabilities if action in cap.actions]


def _holds_right(claims: DelegationClaims, action: str, at: datetime) -> bool:
    """Return whether *claims* authorises *action* at moment *at*.

    A flat grant (no capabilities) holds the right whenever *action* is in
    ``scope_actions``; its own slip window is each caller's own concern, not
    this check. A structured grant holds the right only when some capability
    containing *action* covers *at* (``nbf <= at <= exp``), because the
    capabilities are its effective grant, not ``scope_actions``.
    """
    if not claims.capabilities:
        return action in set(claims.scope_actions)
    return any(nbf <= at <= exp for nbf, exp in _grant_windows(claims, action))


def _scope_widening_axis(child: DelegationClaims, parent: DelegationClaims) -> str | None:
    """Return the first scope axis on which *child* widens *parent*.

    The returned value is suitable for a mint-time refusal reason. ``None``
    means that all static constraints narrow or preserve the parent.
    """
    if not set(child.scope_actions).issubset(set(parent.scope_actions)):
        return "actions"
    for child_path in child.scope_paths:
        normalised_child = _osp.normpath(child_path)
        if not any(
            normalised_child == _osp.normpath(pp)
            or normalised_child.startswith(_osp.normpath(pp) + "/")
            for pp in parent.scope_paths
        ):
            return "paths"
    # temporal attenuation: every window during which the child grants an action must be contained
    # in some window during which the parent grants that action (parent_nbf <= child_nbf and
    # child_exp <= parent_exp). A child can neither start before nor end after the parent's grant,
    # and an action a structured parent never grants has no covering window -> reject. Covers both
    # flat child actions (window = child slip window) and child capability windows.
    for action in set(child.scope_actions):
        parent_windows = _grant_windows(parent, action)
        for child_nbf, child_exp in _grant_windows(child, action):
            if not any(
                parent_nbf <= child_nbf and child_exp <= parent_exp
                for parent_nbf, parent_exp in parent_windows
            ):
                return "capabilities" if parent.capabilities else "time"
    if parent.scope_tools:
        tools_subset = bool(child.scope_tools) and set(child.scope_tools).issubset(
            set(parent.scope_tools)
        )
    else:
        tools_subset = True
    domains_subset = set(child.scope_domains).issubset(set(parent.scope_domains))
    # named_set_ref: a parent with no set constraint lets a child add one (a
    # new restriction is always narrowing). A parent WITH one restricts the
    # child to exactly that set -- a child cannot substitute a different set
    # or drop the constraint, since either would widen what the parent bound.
    if parent.named_set_ref is not None:
        if child.named_set_ref is None:
            return "named_set"
        if child.named_set_ref["content_hash"] != parent.named_set_ref["content_hash"]:
            return "named_set"
    # bounds: a parent bound for a kind ceilings every child's bound for that
    # same kind. A parent with no bound for a kind places no ceiling on it,
    # so a child MAY introduce one (a new restriction is always narrowing).
    # Units must match exactly -- no conversion, ever -- and a child bound in
    # a different unit for a kind the parent also bounds is rejected rather
    # than silently compared.
    # Iterate over the PARENT's bounds, not the child's: unlike scope_domains/
    # scope_tools, which compare as explicit subset relations (a parent with no
    # domains does not grant an arbitrary nonempty child domain set, and an
    # explicit empty child tool list remains explicit), an absent bound means
    # NOT_APPLICABLE at decision time -- no restriction at all. A child
    # that simply omits a bound its parent declared would therefore be
    # UNBOUNDED for that kind, not narrower. Every kind the parent bounds
    # must be restated by the child, exactly like named_set_ref above.
    # Per-grant bounds only. A bound that states an aggregation belongs to a
    # different account of the same kind and is compared below, on its own
    # axis -- comparing the two together would let a shared ceiling stand in
    # for the grant's own, or the reverse.
    parent_bounds_by_kind = {b["kind"]: b for b in parent.bounds if b.get("aggregation") is None}
    child_bounds_by_kind = {b["kind"]: b for b in child.bounds if b.get("aggregation") is None}
    for kind, parent_bound in parent_bounds_by_kind.items():
        child_bound = child_bounds_by_kind.get(kind)
        if child_bound is None:
            return "bounds"
        if child_bound["unit"] != parent_bound["unit"]:
            return "bounds"
        if int(child_bound["amount_scaled"]) > int(parent_bound["amount_scaled"]):
            return "bounds"
        # Cumulative bound window: a parent bound carrying a window_epoch/
        # window_duration_ms pair requires the child to restate BOTH exactly
        # -- a different window is a different accounting period the parent
        # never bounded, not a narrower one (grant vocabulary item 4, owner
        # default: exact match only, no interval-containment sub-windows). A
        # parent bound with no window lets a child add one, same as
        # named_set_ref/bounds above -- a new restriction is always narrowing.
        # window_kind is part of that equality: one budget of N, and N every
        # period forever, are different grants, and neither is narrower than
        # the other by the amount alone.
        if parent_bound.get("window_epoch") is not None and (
            child_bound.get("window_epoch") != parent_bound.get("window_epoch")
            or child_bound.get("window_duration_ms") != parent_bound.get("window_duration_ms")
            or child_bound.get("window_kind") != parent_bound.get("window_kind")
        ):
            return "bounds"
        # applies_to narrowing: on each axis (actions, boundaries), the
        # child's coverage must be a SUPERSET of the parent's, absence
        # expanded to "everywhere" -- a child may make the bound apply to
        # MORE actions/boundaries (more restrictive, narrower), never
        # fewer (never exempt one the parent's bound covered). A parent
        # that already applies everywhere on an axis (absent) requires the
        # child to also apply everywhere on that axis; the child cannot
        # narrow the SET of actions/boundaries covered without exempting
        # something the parent bound.
        parent_applies_to = parent_bound.get("applies_to") or {}
        child_applies_to = child_bound.get("applies_to") or {}
        for side in ("actions", "boundaries"):
            parent_side = parent_applies_to.get(side)
            child_side = child_applies_to.get(side)
            if parent_side is None:
                if child_side is not None:
                    return "applies_to"
                continue
            if child_side is None:
                continue
            if not set(parent_side).issubset(set(child_side)):
                return "applies_to"
    # aggregate_bound: a shared ceiling binds a whole sibling set, so a child
    # inherits it byte for byte -- equality on both sides, like lineage below,
    # never the subset rule the per-grant bounds follow. A child that lowers it
    # would bind its parent and every sibling to a limit the entry never
    # stated; a child that raises or drops it would spend the shared account
    # past that limit; a child that adds one the parent never carried would
    # write a ceiling over its parent's own spending, because both carry the
    # same entry hash and therefore share the account.
    parent_aggregate = sorted(
        (b for b in parent.bounds if b.get("aggregation") is not None),
        key=lambda b: (b["aggregation"], b["kind"]),
    )
    child_aggregate = sorted(
        (b for b in child.bounds if b.get("aggregation") is not None),
        key=lambda b: (b["aggregation"], b["kind"]),
    )
    if child_aggregate != parent_aggregate:
        return "aggregate_bound"
    # approval_quorum: a parent requiring quorum restricts every child to at
    # least as much agreement, never less. A child cannot drop the
    # requirement, substitute a different signer set, or lower the
    # threshold. A parent with no quorum requirement lets a child add one
    # (a new restriction is always narrowing) -- same shape as named_set_ref
    # and bounds above.
    if parent.approval_quorum is not None:
        if child.approval_quorum is None:
            return "quorum"
        parent_signers = parent.approval_quorum["signer_set_ref"]["content_hash"]
        child_signers = child.approval_quorum["signer_set_ref"]["content_hash"]
        if child_signers != parent_signers:
            return "quorum"
        if child.approval_quorum["threshold"] < parent.approval_quorum["threshold"]:
            return "quorum"
    if not tools_subset:
        return "tools"
    if not domains_subset:
        return "domains"
    # lineage: a parent minted from an authority entry through a ratification
    # binds its child to the SAME pair, exactly like named_set_ref above. A
    # child that drops the pair, or carries another entry or another approval,
    # would present authority that traces to a source its parent never
    # received. A parent with no lineage lets a child add one -- a new
    # restriction is always narrowing.
    parent_lineage = (parent.authority_entry_hash, parent.ratification_hash)
    if (
        parent_lineage != (None, None)
        and (
            child.authority_entry_hash,
            child.ratification_hash,
        )
        != parent_lineage
    ):
        return "lineage"
    # aud: a parent addressed to a set of enforcement points binds its child to
    # a subset of that set, the same shape named_set_ref follows. A child that
    # drops the claim would be consumable at any point, which is wider than
    # what the parent granted; a child that names a point the parent never
    # addressed would reach a valve outside the parent's reach. A parent with
    # no audience admits any child audience -- a new restriction is always
    # narrowing.
    if parent.aud is not None and (
        child.aud is None or not set(child.aud).issubset(set(parent.aud))
    ):
        return "aud"
    # revocation_age: a parent that bounds how old a revocation answer may be
    # binds its child to the same bound or a smaller one. A child that raises
    # the number would accept an answer the parent refused; a child that drops
    # the claim would accept any answer the operator allows, which is the same
    # widening by another route -- the aud rule, strict in the drop direction
    # for the same reason. A parent with no bound admits any child bound: a new
    # restriction is always narrowing.
    if parent.max_revocation_age_ms is not None and (
        child.max_revocation_age_ms is None
        or child.max_revocation_age_ms > parent.max_revocation_age_ms
    ):
        return "revocation_age"
    if child.max_depth > parent.max_depth:
        return "max_depth"
    return None


def _is_scope_subset(child: DelegationClaims, parent: DelegationClaims) -> bool:
    """Return True when *child* scope is a subset of *parent* scope."""
    return _scope_widening_axis(child, parent) is None


# Tokens the dump drops: they carry formatting, encoding, or the end of the
# stream, never behaviour.
_DROPPED_TOKENS = frozenset({"COMMENT", "NL", "ENCODING", "ENDMARKER"})
# Tokens the dump keeps by name and empties by text: block structure is
# behaviour, the width of an indent is not.
_EMPTIED_TOKENS = frozenset({"NEWLINE", "INDENT", "DEDENT"})


def _rule_source_dump(rule: Callable[..., Any]) -> str:
    """Return the canonical token stream of *rule*'s source, free of formatting.

    The stream drops comments, blank lines, and the encoding and end markers,
    and empties the text of the newline and indent markers. Reformatting a rule
    therefore leaves the hash where it is, and changing what a rule does, or
    which block a statement sits in, always moves it.

    The token stream is also the same on every supported interpreter, which
    ``ast.dump`` is not: 3.12 prints empty node fields such as ``posonlyargs``
    and ``type_params`` that 3.13 and later omit.
    """
    text = textwrap.dedent(inspect.getsource(rule))
    stream: list[list[str]] = []
    for token in tokenize.generate_tokens(io.StringIO(text).readline):
        name = tokenize.tok_name[token.type]
        if name in _DROPPED_TOKENS:
            continue
        stream.append([name, "" if name in _EMPTIED_TOKENS else token.string])
    return canonical_json_bytes(stream).decode("ascii")


def _compute_attenuation_rule_hash() -> str:
    return sha256_hex(
        canonical_json_bytes(
            {
                "axes": list(AXES),
                "rules": [
                    _rule_source_dump(rule)
                    for rule in (_grant_windows, _scope_widening_axis, _is_scope_subset)
                ],
            }
        )
    )


# The value _compute_attenuation_rule_hash() returns from this module's source,
# on every interpreter the project supports. A source-stripped install has no
# source to read, so the literal answers there.
_ATTENUATION_RULE_HASH_LITERAL = "e17a3c76cc01c883880db9bb44ff09b01795a3532620b29ea1ec0583c73b19f5"


def _resolve_attenuation_rule_hash() -> str:
    """Return the rule hash, computed from source when the source is present.

    A bytecode-only install carries no source text, so ``inspect.getsource``
    raises ``OSError``; a native (Cython) install exposes the rules as extension
    functions, so it raises ``TypeError``. In both cases the literal answers. When the
    source is present, the computed value must equal the literal: a rule edited
    without a moved literal changes what every later ratification binds, and
    that change must not pass in silence.

    The computed value does not depend on the interpreter, so an install that
    reads the source and an install that answers from the literal agree.
    """
    try:
        computed = _compute_attenuation_rule_hash()
    except OSError, TypeError:
        return _ATTENUATION_RULE_HASH_LITERAL
    if computed != _ATTENUATION_RULE_HASH_LITERAL:
        raise RuntimeError(
            "ambit_verify.attenuation rule hash drift: the source computes "
            f"{computed}, the module declares {_ATTENUATION_RULE_HASH_LITERAL}. "
            "Set _ATTENUATION_RULE_HASH_LITERAL to the computed value."
        )
    return computed


_ATTENUATION_RULE_HASH = _resolve_attenuation_rule_hash()


def attenuation_rule_hash() -> str:
    """Return the SHA-256 over the attenuation rule's content, not its label.

    Every ratification binds this hash beside ``rule_version``. A maintainer who
    edits an axis body and forgets to bump ``ATTENUATION_RULE_VERSION`` still
    changes every later ratification, so a reader can tell which rule approved a
    grant.
    """
    return _ATTENUATION_RULE_HASH


__all__ = [
    "ATTENUATION_RULE_VERSION",
    "AXES",
    "attenuation_rule_hash",
]
