"""Independent expectations for retained-byte predicates, not producer pass flags."""

import hashlib
import json
from dataclasses import FrozenInstanceError, replace
from types import MappingProxyType

import pytest

import evidence_braid as api
import evidence_braid.checks as core
from evidence_braid.errors import InputFormatError, ValidationError


def make_plan(rules, inputs):
    return api.CheckPlan(
        plan_id="plan-1",
        workflow_id="workflow-1",
        scope="site/a",
        claim_id="claim-1",
        statement_digest="a" * 64,
        authority_digest="b" * 64,
        evidence_head="c" * 64,
        inputs=tuple(
            api.ArtifactReference(
                identifier,
                "site/a",
                "claim-1",
                hashlib.sha256(raw).hexdigest(),
                len(raw),
                "application/json",
            )
            for identifier, raw in inputs.items()
        ),
        rules=tuple(rules),
    )


def test_actual_retained_false_is_failed_not_producer_approved():
    inputs = {"result": b'{"ok":false,"producer_passed":true}'}
    rule = api.CheckRule("ok", api.CheckOperator.EQUALS, "result", ("ok",), expected=True)
    result = api.evaluate_checks(make_plan([rule], inputs), inputs)
    assert result.outcome is api.CheckOutcome.FAIL
    assert result.results[0].reason is api.CheckReason.PREDICATE_FALSE


def test_json_null_is_present_and_not_the_missing_path_sentinel():
    inputs = {"result": b'{"answer":null}'}
    rules = [
        api.CheckRule("null", api.CheckOperator.EQUALS, "result", ("answer",), expected=None),
        api.CheckRule("missing", api.CheckOperator.EQUALS, "result", ("missing",), expected=None),
        api.CheckRule("present", api.CheckOperator.EXISTS, "result", ("answer",)),
    ]
    result = api.evaluate_checks(make_plan(rules, inputs), inputs)
    assert [row.outcome for row in result.results] == [
        api.CheckOutcome.PASS,
        api.CheckOutcome.UNKNOWN,
        api.CheckOutcome.PASS,
    ]
    assert result.results[1].reason is api.CheckReason.PATH_MISSING
    assert result.outcome is api.CheckOutcome.UNKNOWN


def test_boolean_does_not_equal_integer_across_retained_inputs():
    inputs = {"left": b'{"value":true}', "right": b'{"value":1}'}
    rule = api.CheckRule(
        "strict",
        api.CheckOperator.SAME_VALUE,
        "left",
        ("value",),
        other_artifact_id="right",
        other_path=("value",),
    )
    assert api.evaluate_checks(make_plan([rule], inputs), inputs).outcome is api.CheckOutcome.FAIL


def test_empty_or_duplicate_plan_and_structure_literal_are_not_admitted():
    inputs = {"result": b"{}"}
    with pytest.raises(ValidationError):
        make_plan([], inputs)
    rule = api.CheckRule("present", api.CheckOperator.EXISTS, "result", ())
    with pytest.raises(ValidationError):
        make_plan([rule, rule], inputs)
    with pytest.raises(ValidationError):
        api.CheckRule("object", api.CheckOperator.EQUALS, "result", (), expected={})


def test_work_exhaustion_is_an_error_not_an_unknown_or_partial_result():
    inputs = {"result": b'{"ok":true}'}
    rule = api.CheckRule("ok", api.CheckOperator.EQUALS, "result", ("ok",), expected=True)
    with pytest.raises(api.CheckLimitError):
        api.evaluate_checks(
            make_plan([rule], inputs), inputs, limits=api.CheckLimits(max_work_units=1)
        )


@pytest.mark.parametrize("left", [None, False, True, -1, 0, 1, "", "1", "é"])
@pytest.mark.parametrize("right", [None, False, True, -1, 0, 1, "", "1", "é"])
def test_cross_artifact_scalar_truth_table_has_independent_exact_type_oracle(left, right):
    inputs = {
        "left": json.dumps(left, ensure_ascii=False).encode(),
        "right": json.dumps(right, ensure_ascii=False).encode(),
    }
    rule = api.CheckRule(
        "match", api.CheckOperator.SAME_VALUE, "left", (), other_artifact_id="right", other_path=()
    )
    actual = api.evaluate_checks(make_plan([rule], inputs), inputs)
    # Deliberately independent tagged scalar comparison, not CheckResult/_equal.
    tagged_left = (json.dumps(left, ensure_ascii=False), type(left).__name__)
    tagged_right = (json.dumps(right, ensure_ascii=False), type(right).__name__)
    assert actual.outcome.value == ("pass" if tagged_left == tagged_right else "fail")


@pytest.mark.parametrize(
    "value,expected",
    [
        (-3, "fail"),
        (-2, "pass"),
        (0, "pass"),
        (2, "pass"),
        (3, "fail"),
        (True, "unknown"),
        (None, "unknown"),
        ("0", "unknown"),
        ({}, "unknown"),
        ([], "unknown"),
    ],
)
def test_closed_integer_interval_and_unsupported_types(value, expected):
    inputs = {"input": json.dumps(value).encode()}
    rule = api.CheckRule("range", api.CheckOperator.INTEGER_RANGE, "input", minimum=-2, maximum=2)
    assert api.evaluate_checks(make_plan([rule], inputs), inputs).outcome.value == expected


@pytest.mark.parametrize(
    "left,right,expected",
    [
        (b"", b"", "pass"),
        (b"\x00\xff", b"\x00\xff", "pass"),
        (b"[]", b"[ ]", "fail"),
        (b"not json", b"not json", "pass"),
        (b"a", b"b", "fail"),
    ],
)
def test_bytes_equal_does_not_claim_json_or_normalized_equality(left, right, expected):
    inputs = {"left": left, "right": right}
    rule = api.CheckRule("raw", api.CheckOperator.BYTES_EQUAL, "left", other_artifact_id="right")
    plan = make_plan([rule], inputs)
    plan = replace(
        plan,
        inputs=tuple(replace(item, media_type="application/octet-stream") for item in plan.inputs),
    )
    assert api.evaluate_checks(plan, inputs).outcome.value == expected


@pytest.mark.parametrize(
    "path,expected",
    [
        ((), "pass"),
        (("",), "pass"),
        (("a",), "pass"),
        (("a", 0, "null"), "pass"),
        (("a", 1), "fail"),
        (("a", "0"), "fail"),
        (("a", 0, "null", 0), "fail"),
        (("missing",), "fail"),
        ((0,), "fail"),
    ],
)
def test_exists_uses_typed_paths_and_includes_containers_and_null(path, expected):
    inputs = {"input": b'{"":null,"a":[{"null":null}]}'}
    rule = api.CheckRule("exists", api.CheckOperator.EXISTS, "input", path)
    assert api.evaluate_checks(make_plan([rule], inputs), inputs).outcome.value == expected


@pytest.mark.parametrize(
    "left,right,reason",
    [
        (b"{}", b"{}", "path_missing"),
        (b'{"v":0}', b"{}", "path_missing"),
        (b'{"v":{}}', b'{"v":{}}', "type_unsupported"),
        (b'{"v":0}', b'{"v":[]}', "type_unsupported"),
    ],
)
def test_same_value_does_not_compare_structures_or_confuse_missing(left, right, reason):
    inputs = {"left": left, "right": right}
    rule = api.CheckRule(
        "same",
        api.CheckOperator.SAME_VALUE,
        "left",
        ("v",),
        other_artifact_id="right",
        other_path=("v",),
    )
    actual = api.evaluate_checks(make_plan([rule], inputs), inputs)
    assert actual.results[0].reason.value == reason
    assert actual.outcome is api.CheckOutcome.UNKNOWN


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{",
        b"\xff",
        b'{"duplicate":1,"duplicate":2}',
        b"NaN",
        b"Infinity",
        b"1.0",
        b"1e0",
        b"1e999999999",
        b"9007199254740992",
        b"-9007199254740992",
        b"1" * 1000,
        b'"\\ud800"',
        b'{"\\u0000":0}',
        b'"\\u0000"',
    ],
)
def test_invalid_integer_profile_is_structure_error_not_semantic_unknown(raw):
    inputs = {"input": raw}
    rule = api.CheckRule("exists", api.CheckOperator.EXISTS, "input")
    with pytest.raises(InputFormatError):
        api.evaluate_checks(make_plan([rule], inputs), inputs)


@pytest.mark.parametrize("value", [-9007199254740991, 9007199254740991])
def test_safe_integer_endpoints_are_exact(value):
    inputs = {"input": str(value).encode()}
    rule = api.CheckRule("equal", api.CheckOperator.EQUALS, "input", expected=value)
    assert api.evaluate_checks(make_plan([rule], inputs), inputs).outcome is api.CheckOutcome.PASS


def test_input_parsing_does_not_ignore_malformed_unused_fields():
    inputs = {"input": b'{"ok":true,"unused":1.0}'}
    rule = api.CheckRule("ok", api.CheckOperator.EQUALS, "input", ("ok",), expected=True)
    with pytest.raises(InputFormatError):
        api.evaluate_checks(make_plan([rule], inputs), inputs)


@pytest.mark.parametrize(
    "changes",
    [
        {"operator": "exists"},
        {"path": []},
        {"path": (True,)},
        {"path": (-1,)},
        {"path": (9007199254740992,)},
        {"path": ("x" * 257,)},
        {"path": ("a",) * 33},
        {"path": (None,)},
        {"path": ("\x00",)},
        {"expected": None},
        {"minimum": 1},
        {"maximum": 1},
        {"other_artifact_id": "b"},
        {"other_path": ()},
    ],
)
def test_rule_rejects_wrong_types_and_irrelevant_fields(changes):
    with pytest.raises(ValidationError):
        api.CheckRule(
            **{"rule_id": "r", "operator": api.CheckOperator.EXISTS, "artifact_id": "a", **changes}
        )


@pytest.mark.parametrize(
    "minimum,maximum",
    [(2, 1), (True, 2), (0, False), (None, 1), (-9007199254740992, 0), (0, 9007199254740992)],
)
def test_invalid_interval_configuration_is_not_a_failed_predicate(minimum, maximum):
    with pytest.raises(ValidationError):
        api.CheckRule("r", api.CheckOperator.INTEGER_RANGE, "a", minimum=minimum, maximum=maximum)


@pytest.mark.parametrize(
    "operator,options",
    [
        (api.CheckOperator.EQUALS, {}),
        (api.CheckOperator.EQUALS, {"expected": 1.0}),
        (api.CheckOperator.EQUALS, {"expected": "x" * 4097}),
        (api.CheckOperator.EQUALS, {"expected": []}),
        (api.CheckOperator.SAME_VALUE, {"other_artifact_id": "a"}),
        (api.CheckOperator.BYTES_EQUAL, {"other_artifact_id": "a", "path": ("v",)}),
        (api.CheckOperator.BYTES_EQUAL, {"other_artifact_id": "a", "other_path": ()}),
    ],
)
def test_operator_specific_configuration(operator, options):
    with pytest.raises(ValidationError):
        api.CheckRule("r", operator, "a", **options)


def test_wire_roundtrip_order_and_digest_are_independent_canonical_json():
    inputs = {"b": b"2", "a": b"1"}
    rules = [
        api.CheckRule("z", api.CheckOperator.INTEGER_RANGE, "a", minimum=0, maximum=1),
        api.CheckRule("a", api.CheckOperator.BYTES_EQUAL, "b", other_artifact_id="a"),
    ]
    plan = make_plan(rules, inputs)
    raw = json.dumps(
        plan.to_dict(), sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode()
    assert raw == plan.to_bytes()
    assert hashlib.sha256(raw).hexdigest() == plan.digest
    assert api.parse_check_plan(raw) == plan
    assert [item.artifact_id for item in plan.inputs] == ["a", "b"]
    assert [item.rule_id for item in plan.rules] == ["z", "a"]
    assert replace(plan, rules=tuple(reversed(plan.rules))).digest != plan.digest
    result = api.evaluate_checks(plan, inputs)
    assert result.to_dict()["counts"] == {"pass": 1, "fail": 1, "unknown": 0}
    assert result.digest == hashlib.sha256(result.to_bytes()).hexdigest()
    with pytest.raises(FrozenInstanceError):
        plan.plan_id = "mutation"
    with pytest.raises(InputFormatError):
        api.parse_check_plan(raw + b"\n")


def test_byte_and_node_limits_and_repeated_comparison_work_are_shared():
    inputs = {"a": b"[1,2]", "b": b"[1,2]"}
    rules = [
        api.CheckRule("a", api.CheckOperator.EXISTS, "a"),
        api.CheckRule("b", api.CheckOperator.EXISTS, "b"),
    ]
    plan = make_plan(rules, inputs)
    for changes in (
        {"max_input_bytes": 4},
        {"max_total_input_bytes": 9},
        {"max_json_nodes": 5},
        {"max_inputs": 1},
        {"max_rules": 1},
        {"max_plan_bytes": 1},
        {"max_output_bytes": 1},
    ):
        with pytest.raises(ValidationError):
            api.evaluate_checks(plan, inputs, limits=api.CheckLimits(**changes))
    assert (
        api.evaluate_checks(plan, inputs, limits=api.CheckLimits(max_json_nodes=6)).outcome
        is api.CheckOutcome.PASS
    )
    deep = {"a": b"[[0]]"}
    deep_plan = make_plan([rules[0]], deep)
    with pytest.raises(api.CheckLimitError):
        api.evaluate_checks(deep_plan, deep, limits=api.CheckLimits(max_json_depth=1))
    opaque = {"a": b"a" * 100, "b": b"a" * 100}
    repeated = make_plan(
        [
            api.CheckRule(f"r{i}", api.CheckOperator.BYTES_EQUAL, "a", other_artifact_id="b")
            for i in range(12)
        ],
        opaque,
    )
    report = api.evaluate_checks(repeated, opaque)
    # Input hash + each full byte comparison + result emission, not only input size.
    necessary = len(repeated.to_bytes()) + 200 + 12 * 201 + len(report.to_bytes())
    assert (
        api.evaluate_checks(repeated, opaque, limits=api.CheckLimits(max_work_units=necessary))
        == report
    )
    with pytest.raises(api.CheckLimitError):
        api.evaluate_checks(repeated, opaque, limits=api.CheckLimits(max_work_units=necessary - 1))


def test_commitment_and_exact_inventory_check_precede_semantics_without_mutation():
    inputs = {"a": b"true"}
    plan = make_plan([api.CheckRule("r", api.CheckOperator.EXISTS, "a")], inputs)
    original = inputs.copy()
    for retained in (
        {},
        {"b": b"true"},
        {"a": b"true", "extra": b""},
        {"a": b"bad!"},
        {"a": bytearray(b"true")},
    ):
        with pytest.raises(ValidationError):
            api.evaluate_checks(plan, retained)
    assert api.evaluate_checks(plan, inputs).outcome is api.CheckOutcome.PASS
    assert inputs == original


@pytest.mark.parametrize("value", [None, [], {}, {"operator": 1}, {"operator": "custom(secret)"}])
def test_rule_wire_requires_closed_known_operator_without_echoing_input(value):
    with pytest.raises(ValidationError) as caught:
        api.CheckRule.from_dict(value)
    assert "secret" not in str(caught.value)
    assert caught.value.__cause__ is None


def test_every_operator_roundtrips_its_exact_distinct_wire_fields():
    rules = [
        api.CheckRule("exists", api.CheckOperator.EXISTS, "a", ("", 0)),
        api.CheckRule("eq", api.CheckOperator.EQUALS, "a", expected=None),
        api.CheckRule("range", api.CheckOperator.INTEGER_RANGE, "a", minimum=-1, maximum=2),
        api.CheckRule(
            "same", api.CheckOperator.SAME_VALUE, "a", other_artifact_id="b", other_path=()
        ),
        api.CheckRule("bytes", api.CheckOperator.BYTES_EQUAL, "a", other_artifact_id="b"),
    ]
    for rule in rules:
        assert api.CheckRule.from_dict(rule.to_dict()) == rule
        malformed = {**rule.to_dict(), "irrelevant": None}
        with pytest.raises(ValidationError):
            api.CheckRule.from_dict(malformed)


@pytest.mark.parametrize(
    "field,value",
    [
        ("kind", "other"),
        ("kind", 1),
        ("schema_version", 1.0),
        ("schema_version", "2.0"),
        ("engine_version", "future"),
        ("engine_version", True),
        ("inputs", [None]),
        ("inputs", ()),
        ("rules", [None]),
    ],
)
def test_closed_plan_wire_does_not_guess_versions_or_record_types(field, value):
    plan = make_plan([api.CheckRule("r", api.CheckOperator.EXISTS, "a")], {"a": b"{}"})
    raw = {**plan.to_dict(), field: value}
    with pytest.raises(ValidationError):
        api.CheckPlan.from_dict(raw)
    with pytest.raises(ValidationError):
        api.CheckPlan.from_dict(MappingProxyType(plan.to_dict()))


def test_plan_rejects_unbound_duplicate_unused_and_cross_scope_commitments():
    plan = make_plan([api.CheckRule("r", api.CheckOperator.EXISTS, "a")], {"a": b"{}"})
    item = plan.inputs[0]
    candidates = [
        (),
        [],
        (None,),
        (item, item),
        (replace(item, scope="site/b"),),
        (replace(item, claim_id="other"),),
        (replace(item, media_type="text/plain"),),
        (item, replace(item, artifact_id="unused")),
    ]
    for inputs in candidates:
        with pytest.raises(ValidationError):
            replace(plan, inputs=inputs)
    for rules in ([], (None,), (api.CheckRule("wrong", api.CheckOperator.EXISTS, "undeclared"),)):
        with pytest.raises(ValidationError):
            replace(plan, rules=rules)
    with pytest.raises(api.CheckLimitError):
        replace(
            plan,
            rules=tuple(
                api.CheckRule(f"r{i}", api.CheckOperator.EQUALS, "a", expected="x" * 4096)
                for i in range(64)
            ),
        )


@pytest.mark.parametrize("field", list(api.CheckLimits.__dataclass_fields__))
@pytest.mark.parametrize("value", [0, -1, True, 1.0, 1 << 100])
def test_limits_are_exact_positive_compiled_bounded_integers(field, value):
    with pytest.raises(ValidationError):
        api.CheckLimits(**{field: value})


def test_result_descriptions_validate_types_unique_order_and_derived_outcome():
    valid = api.CheckResult("r", api.CheckOutcome.PASS, api.CheckReason.PASSED)
    for changes in (
        {"outcome": "pass"},
        {"reason": "passed"},
        {"reason": api.CheckReason.PATH_MISSING},
    ):
        with pytest.raises(ValidationError):
            replace(valid, **changes)
    for results in ((), [], (None,), (valid, valid)):
        with pytest.raises(ValidationError):
            api.CheckEvaluation("a" * 64, results)
    unknown = api.CheckResult("unknown", api.CheckOutcome.UNKNOWN, api.CheckReason.PATH_MISSING)
    failed = api.CheckResult("false", api.CheckOutcome.FAIL, api.CheckReason.PREDICATE_FALSE)
    assert api.CheckEvaluation("a" * 64, (unknown, failed)).outcome is api.CheckOutcome.FAIL


def test_public_admission_requires_real_config_and_plain_immutable_input_mapping():
    inputs = {"a": b"true"}
    plan = make_plan([api.CheckRule("r", api.CheckOperator.EXISTS, "a")], inputs)
    for limits in ({}, 1, object()):
        with pytest.raises(ValidationError):
            api.evaluate_checks(plan, inputs, limits=limits)
    with pytest.raises(ValidationError):
        api.evaluate_checks(None, inputs)
    with pytest.raises(ValidationError):
        api.evaluate_checks(plan, MappingProxyType(inputs))
    changed = replace(plan, rules=(*plan.rules, api.CheckRule("r2", api.CheckOperator.EXISTS, "a")))
    with pytest.raises(api.CheckLimitError):
        api.parse_check_plan(changed.to_bytes(), limits=api.CheckLimits(max_rules=1))
    with pytest.raises(api.CheckLimitError):
        api.parse_check_plan(
            plan.to_bytes(), limits=api.CheckLimits(max_work_units=len(plan.to_bytes()))
        )


def test_admitted_immutable_snapshot_survives_later_caller_mapping_mutation(monkeypatch):
    inputs = {"a": b"true"}
    plan = make_plan([api.CheckRule("r", api.CheckOperator.EQUALS, "a", expected=True)], inputs)
    original = core._evaluate

    def mutate_after_snapshot(plan, retained, budget):
        assert retained is not inputs
        inputs["a"] = b"false"
        inputs["extra"] = b"null"
        return original(plan, retained, budget)

    monkeypatch.setattr(core, "_evaluate", mutate_after_snapshot)
    assert api.evaluate_checks(plan, inputs).outcome is api.CheckOutcome.PASS


def test_mapping_size_change_during_admission_is_not_a_partial_evaluation(monkeypatch):
    inputs = {"a": b"true", "b": b"true"}
    plan = make_plan(
        [api.CheckRule("r", api.CheckOperator.BYTES_EQUAL, "a", other_artifact_id="b")], inputs
    )
    original = core._identifier

    def mutate(identifier, path):
        original(identifier, path)
        inputs["extra"] = b"true"

    monkeypatch.setattr(core, "_identifier", mutate)
    with pytest.raises(ValidationError, match="mapping changed"):
        api.evaluate_checks(plan, inputs)
