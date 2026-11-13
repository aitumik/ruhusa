import json
from pathlib import Path

import pytest

from abac import (
    BUILTIN_OPERATORS,
    Policy,
    PolicyValidationError,
    load_policies,
    load_policies_file,
    load_policies_json,
    validate_policies,
)


VALID_POLICY = {
    "id": "allow-read",
    "effect": "allow",
    "actions": ["invoice.read"],
    "resource_types": ["invoice"],
    "condition": {
        "left": "subject.department",
        "op": "==",
        "right": {"attr": "resource.department"},
    },
}


def test_load_policies_from_list():
    policies = load_policies([VALID_POLICY])
    assert len(policies) == 1
    assert policies[0].id == "allow-read"
    assert policies[0].actions == ("invoice.read",)


def test_load_policies_from_wrapper_object():
    policies = load_policies({"policies": [VALID_POLICY]})
    assert [policy.id for policy in policies] == ["allow-read"]


def test_load_policies_from_single_policy_object():
    policies = load_policies(VALID_POLICY)
    assert [policy.id for policy in policies] == ["allow-read"]


def test_policy_defaults():
    policy = load_policies(
        {
            "id": "allow-all",
            "effect": "allow",
            "actions": "*",
        }
    )[0]
    assert policy.resource_types == ("*",)
    assert policy.condition is None
    assert policy.priority == 0
    assert policy.enabled is True
    assert policy.metadata == {}


def test_policy_to_dict_round_trip():
    policy = load_policies([VALID_POLICY])[0]
    loaded_again = load_policies(policy.to_dict())[0]
    assert loaded_again == policy


def test_load_policies_json():
    policies = load_policies_json(json.dumps({"policies": [VALID_POLICY]}))
    assert policies[0].id == "allow-read"


def test_load_policies_file(tmp_path):
    path = tmp_path / "policies.json"
    path.write_text(json.dumps({"policies": [VALID_POLICY]}), encoding="utf-8")
    policies = load_policies_file(path)
    assert policies[0].id == "allow-read"


def test_invalid_json_raises():
    with pytest.raises(PolicyValidationError, match="invalid JSON"):
        load_policies_json("{not json")


def test_unknown_policy_key_is_rejected():
    data = dict(VALID_POLICY)
    data["condtion"] = {}
    errors = validate_policies([data])
    assert any("unknown key" in error for error in errors)


def test_invalid_effect_is_rejected():
    data = dict(VALID_POLICY)
    data["effect"] = "maybe"
    errors = validate_policies([data])
    assert any("effect" in error for error in errors)


def test_missing_actions_is_rejected():
    errors = validate_policies([{"id": "x", "effect": "allow"}])
    assert any("actions" in error for error in errors)


def test_empty_actions_is_rejected():
    errors = validate_policies(
        [{"id": "x", "effect": "allow", "actions": []}]
    )
    assert any("must not be empty" in error for error in errors)


def test_duplicate_policy_ids_are_rejected():
    errors = validate_policies([VALID_POLICY, VALID_POLICY])
    assert any("duplicate policy id" in error for error in errors)


def test_invalid_condition_is_rejected():
    data = dict(VALID_POLICY)
    data["condition"] = {"left": "subject.id", "op": "=="}
    errors = validate_policies([data])
    assert any("requires a 'right' operand" in error for error in errors)


def test_unknown_operator_is_rejected_when_operators_are_known():
    data = dict(VALID_POLICY)
    data["condition"] = {
        "left": "subject.id",
        "op": "bogus",
        "right": 1,
    }
    errors = validate_policies([data], operators=BUILTIN_OPERATORS)
    assert any("unknown operator" in error for error in errors)


def test_invalid_regex_is_rejected():
    data = dict(VALID_POLICY)
    data["condition"] = {
        "left": "subject.department",
        "op": "matches",
        "right": "[",
    }
    errors = validate_policies([data])
    assert any("invalid regular expression" in error for error in errors)


def test_unary_operator_rejects_right_operand():
    data = dict(VALID_POLICY)
    data["condition"] = {
        "left": "subject.department",
        "op": "exists",
        "right": True,
    }
    errors = validate_policies([data])
    assert any("does not take a 'right' operand" in error for error in errors)


def test_left_operand_must_be_an_attribute_or_explicit_literal():
    data = dict(VALID_POLICY)
    data["condition"] = {
        "left": 42,
        "op": "==",
        "right": 42,
    }
    errors = validate_policies([data])
    assert any("left operand" in error for error in errors)


def test_invalid_attribute_path_is_rejected():
    data = dict(VALID_POLICY)
    data["condition"] = {
        "left": "subject..department",
        "op": "==",
        "right": "finance",
    }
    errors = validate_policies([data])
    assert any("invalid attribute path" in error for error in errors)


def test_unknown_container_key_is_rejected():
    errors = validate_policies({"policies": [VALID_POLICY], "extra": True})
    assert any("unknown key" in error for error in errors)


def test_custom_operator_is_accepted_when_registered():
    data = dict(VALID_POLICY)
    data["condition"] = {
        "left": "resource.amount",
        "op": "within_budget",
        "right": 5000,
    }
    operators = {"within_budget": lambda left, right, request: left <= right}
    assert validate_policies([data], operators=operators) == []


def test_policy_objects_are_accepted():
    policy = Policy(
        id="allow",
        effect="allow",
        actions=("invoice.read",),
    )
    assert load_policies([policy])[0].id == "allow"


def test_example_policies_load():
    path = Path(__file__).resolve().parents[1] / "examples" / "policies.json"
    policies = load_policies_file(path)
    assert policies
    assert all(policy.id for policy in policies)
