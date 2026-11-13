from abac import resolve ,MISSING

def test_resolve_returns_subject_attribute():
    request = {"subject": {"department": "finance"}}
    assert resolve("subject.department",request) == "finance"

def test_resolve_returns_resource_attribute():
    request = {"resource": {"amount": 3000}}
    assert resolve("resource.amount",request) == 3000

def test_resolve_missing_attribute_returns_sentinel():
    request = {"subject": {"department": "finance"}}
    resolve("subject.nonexistent",request) is MISSING

def test_resolve_missing_section_returns_sentinel():
    request = {"subject": {"id": 1}}
    assert resolve("environment.time",request) is MISSING

def test_missing_never_equals_missing():
    assert MISSING != MISSING

def test_missing_never_equals_none():
    assert MISSING != None
