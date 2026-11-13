from abac import (
    evaluate_condition,
    evaluate_condition_outcome,
)


def test_equal_attributes_match(request_data):
    condition = {
        "left": "subject.department",
        "op": "==",
        "right": {"attr": "resource.department"},
    }
    assert evaluate_condition(condition, request_data) is True


def test_equal_with_literal(request_data):
    condition = {"left": "subject.role", "op": "==", "right": "manager"}
    assert evaluate_condition(condition, request_data) is True


def test_not_equal(request_data):
    condition = {"left": "resource.status", "op": "!=", "right": "archived"}
    assert evaluate_condition(condition, request_data) is True


def test_less_than(request_data):
    condition = {"left": "resource.amount", "op": "<", "right": 5000}
    assert evaluate_condition(condition, request_data) is True


def test_greater_than_fails(request_data):
    condition = {"left": "resource.amount", "op": ">", "right": 5000}
    assert evaluate_condition(condition, request_data) is False


def test_in_list(request_data):
    condition = {
        "left": "subject.role",
        "op": "in",
        "right": ["manager", "admin"],
    }
    assert evaluate_condition(condition, request_data) is True


def test_attribute_in_attribute_list(request_data):
    condition = {
        "left": "resource.department",
        "op": "in",
        "right": {"attr": "subject.departments"},
    }
    assert evaluate_condition(condition, request_data) is True


def test_list_contains_literal(request_data):
    condition = {
        "left": "subject.roles",
        "op": "contains",
        "right": "manager",
    }
    assert evaluate_condition(condition, request_data) is True


def test_not_in(request_data):
    condition = {
        "left": "subject.role",
        "op": "not_in",
        "right": ["employee", "contractor"],
    }
    assert evaluate_condition(condition, request_data) is True


def test_not_contains(request_data):
    condition = {
        "left": "subject.roles",
        "op": "not_contains",
        "right": "admin",
    }
    assert evaluate_condition(condition, request_data) is True


def test_intersects(request_data):
    condition = {
        "left": "subject.departments",
        "op": "intersects",
        "right": ["operations", "legal"],
    }
    assert evaluate_condition(condition, request_data) is True


def test_subset(request_data):
    condition = {
        "left": {"value": ["finance"]},
        "op": "subset",
        "right": {"attr": "subject.departments"},
    }
    assert evaluate_condition(condition, request_data) is True


def test_superset(request_data):
    condition = {
        "left": "subject.departments",
        "op": "superset",
        "right": ["finance"],
    }
    assert evaluate_condition(condition, request_data) is True


def test_startswith(request_data):
    condition = {
        "left": "subject.department",
        "op": "startswith",
        "right": "fin",
    }
    assert evaluate_condition(condition, request_data) is True


def test_endswith(request_data):
    condition = {
        "left": "subject.department",
        "op": "endswith",
        "right": "ance",
    }
    assert evaluate_condition(condition, request_data) is True


def test_regex_full_match(request_data):
    condition = {
        "left": "subject.department",
        "op": "matches",
        "right": "fin.*",
    }
    assert evaluate_condition(condition, request_data) is True


def test_regex_is_not_a_substring_match(request_data):
    condition = {
        "left": "subject.department",
        "op": "matches",
        "right": "nan",
    }
    assert evaluate_condition(condition, request_data) is False


def test_exists(request_data):
    condition = {"left": "subject.role", "op": "exists"}
    assert evaluate_condition(condition, request_data) is True


def test_missing_does_not_exist(request_data):
    condition = {"left": "subject.missing", "op": "exists"}
    assert evaluate_condition(condition, request_data) is False


def test_not_exists(request_data):
    condition = {"left": "subject.missing", "op": "not_exists"}
    assert evaluate_condition(condition, request_data) is True


def test_is_null_with_literal_none(request_data):
    condition = {"left": {"value": None}, "op": "is_null"}
    assert evaluate_condition(condition, request_data) is True


def test_not_null_with_missing_is_false(request_data):
    condition = {"left": "subject.missing", "op": "not_null"}
    assert evaluate_condition(condition, request_data) is False


def test_missing_attribute_fails_not_equal(request_data):
    condition = {
        "left": "resource.nonexistent",
        "op": "!=",
        "right": "archived",
    }
    assert evaluate_condition(condition, request_data) is False


def test_missing_attribute_is_indeterminate(request_data):
    condition = {
        "left": "resource.nonexistent",
        "op": "==",
        "right": "archived",
    }
    outcome = evaluate_condition_outcome(condition, request_data)
    assert outcome.value is None
    assert outcome.errors
    assert evaluate_condition(condition, request_data) is False


def test_not_with_missing_attribute_is_indeterminate(request_data):
    condition = {
        "not": {
            "left": "resource.nonexistent",
            "op": "==",
            "right": "archived",
        }
    }
    outcome = evaluate_condition_outcome(condition, request_data)
    assert outcome.value is None
    assert evaluate_condition(condition, request_data) is False


def test_type_error_is_indeterminate(request_data):
    condition = {"left": "resource.amount", "op": "<", "right": "lots"}
    outcome = evaluate_condition_outcome(condition, request_data)
    assert outcome.value is None
    assert outcome.errors
    assert evaluate_condition(condition, request_data) is False


def test_unknown_operator_is_indeterminate(request_data):
    condition = {"left": "subject.role", "op": "bogus", "right": "manager"}
    outcome = evaluate_condition_outcome(condition, request_data)
    assert outcome.value is None
    assert "unknown operator" in outcome.errors[0]


def test_all_requires_every_condition(request_data):
    condition = {
        "all": [
            {"left": "subject.role", "op": "==", "right": "manager"},
            {"left": "resource.amount", "op": "<", "right": 1000},
        ]
    }
    assert evaluate_condition(condition, request_data) is False


def test_any_requires_one_condition(request_data):
    condition = {
        "any": [
            {"left": "subject.role", "op": "==", "right": "manager"},
            {"left": "resource.amount", "op": "<", "right": 1000},
        ]
    }
    assert evaluate_condition(condition, request_data) is True


def test_not_inverts_a_condition(request_data):
    condition = {
        "not": {"left": "subject.role", "op": "==", "right": "employee"}
    }
    assert evaluate_condition(condition, request_data) is True


def test_empty_all_is_true(request_data):
    assert evaluate_condition({"all": []}, request_data) is True


def test_empty_any_is_false(request_data):
    assert evaluate_condition({"any": []}, request_data) is False


def test_any_with_true_and_indeterminate_is_true(request_data):
    condition = {
        "any": [
            {"left": "subject.role", "op": "==", "right": "manager"},
            {"left": "resource.nonexistent", "op": "==", "right": "x"},
        ]
    }
    outcome = evaluate_condition_outcome(condition, request_data)
    assert outcome.value is True


def test_all_with_false_and_indeterminate_is_false(request_data):
    condition = {
        "all": [
            {"left": "subject.role", "op": "==", "right": "employee"},
            {"left": "resource.nonexistent", "op": "==", "right": "x"},
        ]
    }
    outcome = evaluate_condition_outcome(condition, request_data)
    assert outcome.value is False


def test_any_with_false_and_indeterminate_is_indeterminate(request_data):
    condition = {
        "any": [
            {"left": "subject.role", "op": "==", "right": "employee"},
            {"left": "resource.nonexistent", "op": "==", "right": "x"},
        ]
    }
    outcome = evaluate_condition_outcome(condition, request_data)
    assert outcome.value is None


def test_custom_operator(request_data):
    condition = {
        "left": "resource.amount",
        "op": "within_budget",
        "right": 5000,
    }
    operators = {
        "within_budget": lambda left, right, request: left <= right,
    }
    assert evaluate_condition(condition, request_data, operators=operators) is True


def test_failed_custom_operator_is_indeterminate(request_data):
    def explode(left, right, request):
        raise RuntimeError("boom")

    condition = {
        "left": "resource.amount",
        "op": "explode",
        "right": 1,
    }
    outcome = evaluate_condition_outcome(
        condition, request_data, operators={"explode": explode}
    )
    assert outcome.value is None
    assert "boom" in outcome.errors[0]


def test_custom_resolver(request_data):
    condition = {
        "left": "subject.effective_roles",
        "op": "contains",
        "right": "manager",
    }
    resolvers = {
        "subject.effective_roles": lambda request, path: ["manager", "employee"]
    }
    assert evaluate_condition(condition, request_data, resolvers=resolvers) is True


def test_literal_value_operand(request_data):
    condition = {
        "left": {"value": "manager"},
        "op": "in",
        "right": {"attr": "subject.roles"},
    }
    assert evaluate_condition(condition, request_data) is True
