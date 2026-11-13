import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from abac import Authorizer, load_policies_file


engine = Authorizer(
    load_policies_file(Path(__file__).with_name("policies.json"))
)


def request(
    *,
    roles,
    departments,
    action="invoice.approve",
    amount=3000,
    department="finance",
    status="draft",
    tenant="acme",
):
    return {
        "subject": {
            "id": 7,
            "roles": roles,
            "departments": departments,
            "tenant": tenant,
        },
        "resource": {
            "type": "invoice",
            "id": 42,
            "amount": amount,
            "department": department,
            "status": status,
            "tenant": tenant,
        },
        "action": action,
    }


CASES = [
    (
        "manager approves a finance invoice",
        request(roles=["manager"], departments=["finance"]),
    ),
    (
        "manager exceeds approval limit",
        request(roles=["manager"], departments=["finance"], amount=20000),
    ),
    (
        "manager tries another department",
        request(
            roles=["manager"],
            departments=["finance"],
            department="operations",
        ),
    ),
    (
        "manager belongs to two departments",
        request(
            roles=["manager"],
            departments=["finance", "operations"],
            department="operations",
        ),
    ),
    (
        "archived invoice is denied",
        request(
            roles=["manager"],
            departments=["finance"],
            status="archived",
        ),
    ),
    (
        "admin can update settings",
        request(
            roles=["admin"],
            departments=[],
            action="settings.update",
        ),
    ),
]


def main():
    for label, payload in CASES:
        decision = engine.authorize(payload)
        result = "ALLOW" if decision.allowed else "DENY"
        print(f"{result:5}  {label}")
        print(f"       {decision.reason}")


if __name__ == "__main__":
    main()
