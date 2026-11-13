from abac import Authorizer, Decision


ALLOW_READ = {
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


def test_default_deny_with_no_policies(request_data):
    decision = Authorizer([]).authorize(request_data)
    assert decision.allowed is False
    assert decision.determining_policy is None
    assert "default deny" in decision.reason


def test_allow_policy_grants_access(request_data):
    decision = Authorizer([ALLOW_READ]).authorize(request_data | {"action": "invoice.read"})
    assert decision.allowed is True
    assert decision.effect == "allow"
    assert decision.determining_policy == "allow-read"


def test_deny_overrides_allow(request_data):
    policies = [
        ALLOW_READ,
        {
            "id": "deny-finance",
            "effect": "deny",
            "actions": ["invoice.read"],
            "resource_types": ["invoice"],
        },
    ]
    decision = Authorizer(policies).authorize(
        request_data | {"action": "invoice.read"}
    )
    assert decision.allowed is False
    assert decision.determining_policy == "deny-finance"


def test_deny_policy_only_applies_when_condition_matches(request_data):
    policies = [
        {
            "id": "deny-archived",
            "effect": "deny",
            "actions": ["invoice.read"],
            "resource_types": ["invoice"],
            "condition": {
                "left": "resource.status",
                "op": "==",
                "right": "archived",
            },
        },
        ALLOW_READ,
    ]
    decision = Authorizer(policies).authorize(
        request_data | {"action": "invoice.read"}
    )
    assert decision.allowed is True


def test_action_glob_matches(request_data):
    policy = dict(ALLOW_READ)
    policy["id"] = "allow-invoice-star"
    policy["actions"] = ["invoice.*"]
    decision = Authorizer([policy]).authorize(
        request_data | {"action": "invoice.approve"}
    )
    assert decision.allowed is True


def test_resource_type_glob_matches(request_data):
    policy = dict(ALLOW_READ)
    policy["id"] = "allow-invoice-star"
    policy["resource_types"] = ["invoice*"]
    decision = Authorizer([policy]).authorize(
        request_data | {"action": "invoice.read"}
    )
    assert decision.allowed is True


def test_typed_policy_does_not_match_missing_resource_type(request_data):
    request = {"action": "invoice.read", "subject": {"department": "finance"}}
    decision = Authorizer([ALLOW_READ]).authorize(request)
    assert decision.allowed is False


def test_wildcard_policy_matches_missing_resource_type():
    policy = {
        "id": "allow-all",
        "effect": "allow",
        "actions": ["*"],
        "resource_types": ["*"],
    }
    decision = Authorizer([policy]).authorize({"action": "anything"})
    assert decision.allowed is True


def test_wrong_action_does_not_match(request_data):
    decision = Authorizer([ALLOW_READ]).authorize(
        request_data | {"action": "invoice.delete"}
    )
    assert decision.allowed is False


def test_missing_action_is_denied(request_data):
    decision = Authorizer([ALLOW_READ]).authorize({"subject": request_data["subject"]})
    assert decision.allowed is False
    assert "action" in decision.reason


def test_disabled_policy_is_ignored(request_data):
    policy = dict(ALLOW_READ)
    policy["enabled"] = False
    decision = Authorizer([policy]).authorize(
        request_data | {"action": "invoice.read"}
    )
    assert decision.allowed is False


def test_priority_controls_determining_deny_policy(request_data):
    policies = [
        {
            "id": "deny-low",
            "effect": "deny",
            "actions": ["invoice.read"],
            "priority": 1,
        },
        {
            "id": "deny-high",
            "effect": "deny",
            "actions": ["invoice.read"],
            "priority": 10,
        },
    ]
    decision = Authorizer(policies).authorize(
        request_data | {"action": "invoice.read"}
    )
    assert decision.determining_policy == "deny-high"


def test_decision_contains_evaluations(request_data):
    decision = Authorizer([ALLOW_READ]).authorize(
        request_data | {"action": "invoice.read"}
    )
    evaluation = decision.evaluations[0]
    assert evaluation.policy_id == "allow-read"
    assert evaluation.scope_matched is True
    assert evaluation.condition_result is True
    assert evaluation.matched is True


def test_non_matching_scope_is_recorded(request_data):
    decision = Authorizer([ALLOW_READ]).authorize(
        request_data | {"action": "invoice.delete"}
    )
    evaluation = decision.evaluations[0]
    assert evaluation.scope_matched is False
    assert evaluation.matched is False


def test_indeterminate_allow_does_not_grant_access(request_data):
    policy = dict(ALLOW_READ)
    policy["condition"] = {
        "left": "subject.nonexistent",
        "op": "==",
        "right": "finance",
    }
    decision = Authorizer([policy]).authorize(
        request_data | {"action": "invoice.read"}
    )
    assert decision.allowed is False
    assert decision.evaluations[0].condition_result is None
    assert decision.errors


def test_indeterminate_deny_is_skipped_by_default(request_data):
    policies = [
        ALLOW_READ,
        {
            "id": "deny-unknown",
            "effect": "deny",
            "actions": ["invoice.read"],
            "condition": {
                "left": "subject.nonexistent",
                "op": "==",
                "right": "x",
            },
        },
    ]
    decision = Authorizer(policies).authorize(
        request_data | {"action": "invoice.read"}
    )
    assert decision.allowed is True


def test_indeterminate_deny_can_be_strict(request_data):
    policies = [
        ALLOW_READ,
        {
            "id": "deny-unknown",
            "effect": "deny",
            "actions": ["invoice.read"],
            "condition": {
                "left": "subject.nonexistent",
                "op": "==",
                "right": "x",
            },
        },
    ]
    decision = Authorizer(policies, indeterminate_deny=True).authorize(
        request_data | {"action": "invoice.read"}
    )
    assert decision.allowed is False
    assert decision.determining_policy == "deny-unknown"


def test_custom_resolver_is_used(request_data):
    policy = {
        "id": "allow-effective-manager",
        "effect": "allow",
        "actions": ["invoice.read"],
        "condition": {
            "left": "subject.effective_roles",
            "op": "contains",
            "right": "manager",
        },
    }
    engine = Authorizer(
        [policy],
        resolvers={
            "subject.effective_roles": lambda request, path: ["manager", "employee"]
        },
    )
    assert engine.is_allowed(request_data | {"action": "invoice.read"}) is True


def test_custom_operator_is_used(request_data):
    policy = {
        "id": "allow-within-budget",
        "effect": "allow",
        "actions": ["invoice.read"],
        "condition": {
            "left": "resource.amount",
            "op": "within_budget",
            "right": 5000,
        },
    }
    engine = Authorizer(
        [policy],
        operators={
            "within_budget": lambda left, right, request: left <= right,
        },
    )
    assert engine.is_allowed(request_data | {"action": "invoice.read"}) is True


def test_custom_operator_failure_is_recorded(request_data):
    def explode(left, right, request):
        raise RuntimeError("boom")

    policy = {
        "id": "allow-explode",
        "effect": "allow",
        "actions": ["invoice.read"],
        "condition": {
            "left": "resource.amount",
            "op": "explode",
            "right": 1,
        },
    }
    decision = Authorizer([policy], operators={"explode": explode}).authorize(
        request_data | {"action": "invoice.read"}
    )
    assert decision.allowed is False
    assert any("boom" in error for error in decision.errors)


def test_decision_truthiness(request_data):
    decision = Authorizer([ALLOW_READ]).authorize(
        request_data | {"action": "invoice.read"}
    )
    assert isinstance(decision, Decision)
    assert bool(decision) is True


def test_first_allow_in_priority_order_is_determining(request_data):
    policies = [
        ALLOW_READ,
        {
            "id": "allow-higher",
            "effect": "allow",
            "actions": ["invoice.read"],
            "priority": 5,
        },
    ]
    decision = Authorizer(policies).authorize(
        request_data | {"action": "invoice.read"}
    )
    assert decision.determining_policy == "allow-higher"


def test_invalid_operator_registration_is_rejected():
    try:
        Authorizer([], operators={"bad": "not callable"})
    except TypeError as exc:
        assert "callable" in str(exc)
    else:
        raise AssertionError("expected TypeError")


def test_invalid_resolver_registration_is_rejected():
    try:
        Authorizer([], resolvers={"subject.role": "not callable"})
    except TypeError as exc:
        assert "callable" in str(exc)
    else:
        raise AssertionError("expected TypeError")
