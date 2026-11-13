from abac import Authorizer


POLICIES = [
    {
        "id": "employee-read-own-profile",
        "effect": "allow",
        "actions": ["profile.read"],
        "resource_types": ["profile"],
        "condition": {
            "left": "subject.id",
            "op": "==",
            "right": {"attr": "resource.owner_id"},
        },
    },
    {
        "id": "manager-approve",
        "effect": "allow",
        "actions": ["invoice.approve"],
        "resource_types": ["invoice"],
        "condition": {
            "all": [
                {
                    "left": "subject.roles",
                    "op": "contains",
                    "right": "manager",
                },
                {
                    "left": "resource.department",
                    "op": "in",
                    "right": {"attr": "subject.departments"},
                },
                {
                    "left": "resource.amount",
                    "op": "<=",
                    "right": 10000,
                },
            ]
        },
    },
    {
        "id": "controller-approve-high",
        "effect": "allow",
        "actions": ["invoice.approve"],
        "resource_types": ["invoice"],
        "condition": {
            "all": [
                {
                    "left": "subject.roles",
                    "op": "contains",
                    "right": "controller",
                },
                {
                    "left": "resource.department",
                    "op": "in",
                    "right": {"attr": "subject.departments"},
                },
                {
                    "left": "resource.amount",
                    "op": "<=",
                    "right": 100000,
                },
            ]
        },
    },
    {
        "id": "deny-cross-department",
        "effect": "deny",
        "actions": ["invoice.*"],
        "resource_types": ["invoice"],
        "condition": {
            "not": {
                "left": "resource.department",
                "op": "in",
                "right": {"attr": "subject.departments"},
            }
        },
    },
    {
        "id": "deny-archived",
        "effect": "deny",
        "actions": ["invoice.*"],
        "resource_types": ["invoice"],
        "condition": {
            "left": "resource.status",
            "op": "in",
            "right": ["archived", "void"],
        },
    },
    {
        "id": "admin-all",
        "effect": "allow",
        "actions": ["*"],
        "resource_types": ["*"],
        "condition": {
            "left": "subject.roles",
            "op": "contains",
            "right": "admin",
        },
    },
    {
        "id": "tenant-document-read",
        "effect": "allow",
        "actions": ["document.read"],
        "resource_types": ["document"],
        "condition": {
            "left": "subject.tenant",
            "op": "==",
            "right": {"attr": "resource.tenant"},
        },
    },
]


def make_request(
    *,
    roles,
    departments,
    action="invoice.approve",
    amount=3000,
    department="finance",
    status="draft",
    subject_id=7,
    owner_id=7,
    tenant="acme",
    resource_type="invoice",
):
    return {
        "subject": {
            "id": subject_id,
            "roles": roles,
            "departments": departments,
            "tenant": tenant,
        },
        "resource": {
            "type": resource_type,
            "id": 42,
            "amount": amount,
            "department": department,
            "status": status,
            "owner_id": owner_id,
            "tenant": tenant,
        },
        "action": action,
    }


def engine():
    return Authorizer(POLICIES)


def test_department_manager_can_approve_within_limit():
    decision = engine().authorize(
        make_request(roles=["manager"], departments=["finance"])
    )
    assert decision.allowed is True
    assert decision.determining_policy == "manager-approve"


def test_department_manager_cannot_approve_over_limit():
    decision = engine().authorize(
        make_request(
            roles=["manager"],
            departments=["finance"],
            amount=20000,
        )
    )
    assert decision.allowed is False


def test_controller_can_approve_higher_amount():
    decision = engine().authorize(
        make_request(
            roles=["controller"],
            departments=["finance"],
            amount=50000,
        )
    )
    assert decision.allowed is True
    assert decision.determining_policy == "controller-approve-high"


def test_cross_department_is_denied_even_when_allow_condition_matches():
    decision = engine().authorize(
        make_request(
            roles=["manager"],
            departments=["finance"],
            department="operations",
        )
    )
    assert decision.allowed is False
    assert decision.determining_policy == "deny-cross-department"


def test_multi_department_membership_allows_operations():
    decision = engine().authorize(
        make_request(
            roles=["manager"],
            departments=["finance", "operations"],
            department="operations",
        )
    )
    assert decision.allowed is True


def test_archived_invoice_is_denied_even_for_manager():
    decision = engine().authorize(
        make_request(
            roles=["manager"],
            departments=["finance"],
            status="archived",
        )
    )
    assert decision.allowed is False
    assert decision.determining_policy == "deny-archived"


def test_admin_can_use_any_action():
    decision = engine().authorize(
        make_request(
            roles=["admin"],
            departments=[],
            action="settings.update",
        )
    )
    assert decision.allowed is True
    assert decision.determining_policy == "admin-all"


def test_employee_can_read_own_profile():
    decision = engine().authorize(
        make_request(
            roles=["employee"],
            departments=["finance"],
            action="profile.read",
            subject_id=7,
            owner_id=7,
            resource_type="profile",
        )
    )
    assert decision.allowed is True
    assert decision.determining_policy == "employee-read-own-profile"


def test_employee_cannot_read_another_profile():
    decision = engine().authorize(
        make_request(
            roles=["employee"],
            departments=["finance"],
            action="profile.read",
            subject_id=7,
            owner_id=8,
            resource_type="profile",
        )
    )
    assert decision.allowed is False


def test_tenant_isolation():
    same_tenant = engine().authorize(
        make_request(
            roles=["employee"],
            departments=["finance"],
            action="document.read",
            tenant="acme",
            resource_type="document",
        )
    )
    assert same_tenant.allowed is True

    request = make_request(
        roles=["employee"],
        departments=["finance"],
        action="document.read",
        tenant="acme",
        resource_type="document",
    )
    request["resource"]["tenant"] = "other"
    assert engine().authorize(request).allowed is False


def test_role_hierarchy_via_custom_resolver():
    policy = {
        "id": "effective-manager",
        "effect": "allow",
        "actions": ["invoice.approve"],
        "resource_types": ["invoice"],
        "condition": {
            "left": "subject.effective_roles",
            "op": "contains",
            "right": "manager",
        },
    }

    def expand_roles(request, path):
        roles = set(request["subject"].get("roles", []))
        if "senior_manager" in roles:
            roles.add("manager")
        return sorted(roles)

    engine_with_resolver = Authorizer(
        [policy],
        resolvers={"subject.effective_roles": expand_roles},
    )
    decision = engine_with_resolver.authorize(
        make_request(roles=["senior_manager"], departments=["finance"])
    )
    assert decision.allowed is True
    assert decision.determining_policy == "effective-manager"


def test_decision_explains_denial():
    decision = engine().authorize(
        make_request(roles=["employee"], departments=["finance"])
    )
    assert decision.allowed is False
    assert decision.reason == "no matching allow policy (default deny)"
    assert decision.evaluations
