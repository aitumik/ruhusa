from abac import MISSING, resolve


REQUEST = {
    "subject": {"id": 7, "department": "finance"},
    "resource": {"amount": 3000, "tags": ["a", "b"]},
}


def test_resolve_returns_subject_attribute():
    assert resolve("subject.department", REQUEST) == "finance"


def test_resolve_returns_resource_attribute():
    assert resolve("resource.amount", REQUEST) == 3000


def test_resolve_supports_list_indices():
    assert resolve("resource.tags.1", REQUEST) == "b"


def test_resolve_missing_attribute_returns_sentinel():
    assert resolve("subject.nonexistent", REQUEST) is MISSING


def test_resolve_missing_section_returns_sentinel():
    assert resolve("environment.time", REQUEST) is MISSING


def test_resolve_index_out_of_range_returns_sentinel():
    assert resolve("resource.tags.9", REQUEST) is MISSING


def test_resolve_non_numeric_list_segment_returns_sentinel():
    assert resolve("resource.tags.first", REQUEST) is MISSING


def test_missing_never_equals_missing():
    assert MISSING != MISSING


def test_missing_never_equals_none():
    assert MISSING != None


def test_custom_resolver_exact_path():
    resolvers = {
        "subject.effective_roles": lambda request, path: ["manager", "employee"]
    }
    assert resolve("subject.effective_roles", REQUEST, resolvers) == [
        "manager",
        "employee",
    ]


def test_custom_resolver_receives_request_and_path():
    seen = {}

    def resolver(request, path):
        seen["request"] = request
        seen["path"] = path
        return "computed"

    assert resolve("subject.computed", REQUEST, {"subject.computed": resolver}) == (
        "computed"
    )
    assert seen["request"] is REQUEST
    assert seen["path"] == "subject.computed"


def test_custom_resolver_prefix_uses_longest_match():
    resolvers = {
        "subject.": lambda request, path: "broad",
        "subject.effective.": lambda request, path: "narrow",
    }
    assert resolve("subject.effective.roles", REQUEST, resolvers) == "narrow"


def test_custom_resolver_exact_beats_prefix():
    resolvers = {
        "subject.department": lambda request, path: "exact",
        "subject.": lambda request, path: "prefix",
    }
    assert resolve("subject.department", REQUEST, resolvers) == "exact"


def test_custom_resolver_missing_falls_back_to_request():
    resolvers = {"subject.department": lambda request, path: MISSING}
    assert resolve("subject.department", REQUEST, resolvers) == "finance"
