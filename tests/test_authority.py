from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from evidence_braid.authority import (
    ActorKind,
    ArtifactReference,
    AuthorityPolicy,
    AuthorityRole,
    ScopeGrant,
    WorkflowAction,
    WorkflowActor,
    WorkflowTransition,
)
from evidence_braid.errors import ValidationError


def grant():
    return ScopeGrant("site/a", AuthorityRole.AUTHOR)


def actor():
    return WorkflowActor("alice", ActorKind.HUMAN, (grant(),))


def policy():
    return AuthorityPolicy("policy", (actor(),))


def transition():
    return WorkflowTransition(
        "create", WorkflowAction.CREATE, "alice", "site/a", "claim", 0, statement="A claim."
    )


@pytest.mark.parametrize("value", [None, True, "", " a", "a ", "*", "site/💡", "a" * 129])
def test_scope_identifiers_are_bounded_exact_and_never_wildcards(value):
    with pytest.raises(ValidationError, match="identifier"):
        ScopeGrant(value, AuthorityRole.AUTHOR)


def test_exact_scope_has_no_prefix_or_hierarchical_permission():
    assert actor().permits("site/a", AuthorityRole.AUTHOR)
    assert not actor().permits("site/a/child", AuthorityRole.AUTHOR)
    assert not actor().permits("site", AuthorityRole.AUTHOR)
    assert not actor().permits("site/a", AuthorityRole.REVIEWER)


@pytest.mark.parametrize(
    "value",
    [0, True, -1, 17, 1.0, 10**10000],
    ids=["zero", "boolean", "negative", "above-max", "float", "huge-integer"],
)
def test_quorum_requires_small_positive_builtin_integer(value):
    with pytest.raises(ValidationError, match="integer"):
        replace(policy(), approval_quorum=value)


@pytest.mark.parametrize(
    "changes",
    [
        {"kind": "human"},
        {"grants": []},
        {"grants": ()},
        {"grants": ("author",)},
        {"grants": (grant(),) * 129},
        {"grants": (grant(), grant())},
    ],
)
def test_actor_constructor_rejects_invalid_and_duplicate_grants(changes):
    with pytest.raises(ValidationError):
        replace(actor(), **changes)


def test_grant_and_policy_require_typed_declarations():
    with pytest.raises(ValidationError, match="AuthorityRole"):
        ScopeGrant("site/a", "author")
    for actors in ([], (), ("actor",), (actor(),) * 257, (actor(), actor())):
        with pytest.raises(ValidationError):
            replace(policy(), actors=actors)


@pytest.mark.parametrize("kind", [True, "unknown"])
def test_unknown_or_nonstring_actor_enum_rejected(kind):
    raw = actor().to_dict()
    raw["kind"] = kind
    with pytest.raises(ValidationError, match="enum"):
        WorkflowActor.from_dict(raw)


@pytest.mark.parametrize("raw", [None, {}, {"scope": "site/a", "role": "author", "extra": 1}])
def test_grant_shape_is_closed(raw):
    with pytest.raises(ValidationError):
        ScopeGrant.from_dict(raw)


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": "2.0"},
        {"kind": "other"},
        {"actors": None},
        {"actors": [None] * 257},
    ],
)
def test_policy_document_bounds_and_version(changes):
    with pytest.raises(ValidationError):
        AuthorityPolicy.from_dict({**policy().to_dict(), **changes})


def test_authority_snapshot_canonical_order_and_digest():
    first = ScopeGrant("site/b", AuthorityRole.REVIEWER)
    expanded = replace(actor(), grants=(first, grant()))
    other = replace(actor(), actor_id="bob")
    one = AuthorityPolicy("policy", (other, expanded))
    two = AuthorityPolicy("policy", (expanded, other))
    assert one == two and one.digest == two.digest
    assert AuthorityPolicy.from_dict(one.to_dict()) == one
    document = one.to_dict()
    document["actors"][0]["grants"].clear()
    assert len(one.actors[0].grants) == 2
    with pytest.raises(FrozenInstanceError):
        one.approval_quorum = 2


@pytest.mark.parametrize("value", [None, "", " padded ", "x" * 8193, "bad\x00text"])
def test_statement_is_bounded_canonical_text(value):
    with pytest.raises(ValidationError):
        replace(transition(), statement=value)


@pytest.mark.parametrize(
    "changes",
    [
        {"action": "create"},
        {"expected_revision": True},
        {"expected_revision": -1},
        {"expected_revision": 10001},
        {"reference_id": "not-applicable"},
        {"reference_digest": "0" * 64},
        {"reason": "not-applicable"},
    ],
)
def test_transition_constructor_rejects_irrelevant_fields_and_invalid_types(changes):
    with pytest.raises(ValidationError):
        replace(transition(), **changes)


@pytest.mark.parametrize("action", list(WorkflowAction)[1:])
def test_statement_is_exclusive_to_create(action):
    with pytest.raises(ValidationError, match="only create"):
        replace(transition(), action=action)


@pytest.mark.parametrize("action", [WorkflowAction.REJECT, WorkflowAction.REVOKE])
def test_adverse_decisions_require_recorded_reason(action):
    with pytest.raises(ValidationError):
        replace(transition(), action=action, statement=None)
    command = replace(transition(), action=action, statement=None, reason="Supporting reason.")
    assert WorkflowTransition.from_dict(command.to_dict()) == command


@pytest.mark.parametrize("action", [WorkflowAction.BIND_EVIDENCE, WorkflowAction.BIND_ARTIFACT])
def test_bind_requires_both_identity_and_sha256(action):
    for changes in (
        {},
        {"reference_id": "target"},
        {"reference_id": "target", "reference_digest": "bad"},
    ):
        with pytest.raises(ValidationError):
            replace(transition(), action=action, statement=None, **changes)


def test_transition_document_is_closed():
    raw = transition().to_dict()
    raw["pretend_authorized"] = True
    with pytest.raises(ValidationError, match="exactly"):
        WorkflowTransition.from_dict(raw)


@pytest.mark.parametrize(
    "changes",
    [
        {"size_bytes": True},
        {"size_bytes": -1},
        {"size_bytes": 64 * 1024 * 1024 + 1},
        {"sha256": "F" * 64},
        {"media_type": "x" * 129},
        {"media_type": " "},
    ],
)
def test_artifact_commitment_bounds(changes):
    base = ArtifactReference("artifact", "site/a", "claim", "0" * 64, 0, "application/octet-stream")
    with pytest.raises(ValidationError):
        replace(base, **changes)
