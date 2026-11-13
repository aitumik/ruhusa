import pytest


@pytest.fixture
def request_data():
    return {
        "subject": {
            "id": 7,
            "department": "finance",
            "departments": ["finance", "operations"],
            "role": "manager",
            "roles": ["manager"],
        },
        "resource": {
            "type": "invoice",
            "id": 42,
            "amount": 3000,
            "department": "finance",
            "status": "draft",
            "owner_id": 7,
        },
        "action": "invoice.approve",
        "environment": {"ip": "10.0.0.1"},
    }
