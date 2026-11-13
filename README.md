# ruhusa

A small, dependency-free Attribute-Based Access Control (ABAC) library for
Python.

Policies are plain dictionaries and therefore JSON-friendly. Conditions are
composable data, and the decision point uses **deny-overrides** with a
**default deny**.

This makes it practical for business systems with multiple departments,
multiple roles, approval limits, tenant isolation, and other fine-grained
rules without hardcoding an organization model into the library.

## Quick start

```python
from abac import Authorizer, load_policies_file

engine = Authorizer(load_policies_file("examples/policies.json"))

request = {
    "subject": {
        "id": 7,
        "roles": ["manager"],
        "departments": ["finance"],
        "tenant": "acme",
    },
    "resource": {
        "type": "invoice",
        "id": 42,
        "amount": 3000,
        "department": "finance",
        "status": "draft",
        "tenant": "acme",
    },
    "action": "invoice.approve",
}

decision = engine.authorize(request)

decision.allowed             # True
decision.effect              # "allow"
decision.determining_policy  # "manager-approve"
decision.reason              # "allowed by policy 'manager-approve'"
decision.evaluations         # audit trail for every policy
```

There are no third-party runtime dependencies.

## Request model

A request is any mapping. These keys have conventional meaning:

| Key | Meaning |
| --- | --- |
| `subject` | The actor: user, service, department memberships, roles, tenant, etc. |
| `resource` | The thing being accessed. `resource.type` is used for policy scoping. |
| `action` | The operation being attempted, e.g. `invoice.approve`. Required. |
| `environment` | Optional context such as time, IP address, or request source. |
| `context` | Optional application-specific data, available to conditions. |

Each of these can contain arbitrary nested data. Dot paths resolve through
dictionaries and numeric list indices:

```python
resolve("subject.department", request)
resolve("resource.owner.id", request)
resolve("subject.departments.0", request)
```

Departments and roles are **not hardcoded**. They are just attributes:

```json
{
  "subject": {
    "roles": ["manager"],
    "departments": ["finance", "operations"]
  }
}
```

This is what allows arbitrary resolution logic through custom resolvers and
custom operators.

## Conditions

A condition is one of:

- a leaf comparison: `{"left": ..., "op": ..., "right": ...}`
- `{"all": [condition, ...]}`
- `{"any": [condition, ...]}`
- `{"not": condition}`

### Operands

| Form | Meaning |
| --- | --- |
| `"subject.department"` | Attribute path. A string `left` is always a path. |
| `{"attr": "resource.department"}` | Explicit attribute path. |
| `{"value": ...}` | Explicit literal value. |
| any other JSON value | Literal value on the right side. |

Because attribute references are explicit, policy authors do not have to guess
whether `"resource.department"` is a literal string or a path.

```json
{
  "all": [
    {"left": "subject.roles", "op": "contains", "right": "manager"},
    {
      "left": "subject.department",
      "op": "==",
      "right": {"attr": "resource.department"}
    },
    {"left": "resource.amount", "op": "<=", "right": 10000},
    {
      "not": {
        "left": "resource.status",
        "op": "in",
        "right": ["archived", "void"]
      }
    }
  ]
}
```

### Operators

| Operator | Behavior |
| --- | --- |
| `==`, `!=` | Equality and inequality. No implicit type coercion. |
| `<`, `<=`, `>`, `>=` | Ordering comparisons. |
| `in`, `not_in` | Left value in right collection (list, dict keys, or string). |
| `contains`, `not_contains` | Right value in left collection. |
| `intersects` | Two collections share at least one item. |
| `subset` | Every item in the left collection exists in the right collection. |
| `superset` | Every item in the right collection exists in the left collection. |
| `startswith`, `endswith` | String prefix/suffix checks. |
| `matches` | Regular-expression full match (`re.fullmatch`). |
| `exists`, `not_exists` | Whether an attribute exists. |
| `is_null`, `not_null` | Whether an attribute is literally `None`. |

Examples:

```json
{"left": "subject.role", "op": "in", "right": ["manager", "admin"]}
{"left": "subject.roles", "op": "contains", "right": "manager"}
{"left": "resource.department", "op": "in", "right": {"attr": "subject.departments"}}
{"left": "subject.department", "op": "matches", "right": "fin.*"}
{"left": "resource.status", "op": "not_in", "right": ["archived", "void"]}
```

### Missing attributes and indeterminate results

Conditions are evaluated in three states: true, false, and indeterminate.

- A missing attribute, incompatible operand type, or failed operator produces
  an indeterminate result.
- An indeterminate condition never grants access.
- `not` does **not** turn an indeterminate result into true. This prevents a
  missing attribute from accidentally satisfying a negated condition.
- `exists` and `not_exists` are the explicit way to test for missing data.

`evaluate_condition()` returns a plain boolean and is true only when the
condition is definitely true. Use `evaluate_condition_outcome()` if you need
the three-state result and error details.

## Policies

```json
{
  "id": "manager-approve",
  "description": "Managers may approve invoices in their departments up to 10,000.",
  "effect": "allow",
  "actions": ["invoice.approve"],
  "resource_types": ["invoice"],
  "condition": {
    "all": [
      {"left": "subject.roles", "op": "contains", "right": "manager"},
      {
        "left": "resource.department",
        "op": "in",
        "right": {"attr": "subject.departments"}
      },
      {"left": "resource.amount", "op": "<=", "right": 10000}
    ]
  },
  "priority": 10,
  "enabled": true,
  "metadata": {}
}
```

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Unique policy identifier. |
| `effect` | yes | `allow` or `deny`. |
| `actions` | yes | String or list of strings. Glob patterns are supported. |
| `resource_types` | no | Defaults to `"*"`. Glob patterns are supported. |
| `condition` | no | Defaults to always true when omitted. |
| `priority` | no | Integer used for deterministic ordering in audit output. |
| `description` | no | Human-readable description. |
| `enabled` | no | Defaults to `true`. |
| `metadata` | no | Arbitrary application-specific data. |

Unknown policy keys are rejected to catch typos. Duplicate IDs are rejected.
Validation errors include a path such as
`policies[2].condition.all[0].right`.

### Loading policies

```python
from abac import (
    load_policies,
    load_policies_json,
    load_policies_file,
    validate_policies,
)

policies = load_policies([...])           # list or single policy dict
policies = load_policies({"policies": [...]})
policies = load_policies_json(text)
policies = load_policies_file("policies.json")

problems = validate_policies({"policies": [...]})
if problems:
    print("\n".join(problems))
```

Custom operators can be supplied during validation so that names are checked
against the registry:

```python
policies = load_policies(data, operators={"within_budget": my_operator})
```

## Decision engine

```python
from abac import Authorizer

engine = Authorizer(
    policies,
    resolvers={...},          # optional attribute resolvers
    operators={...},          # optional custom operators
    indeterminate_deny=False, # optional strict deny behavior
)

decision = engine.authorize(request)
allowed = engine.is_allowed(request)
```

### Combining semantics

1. Disabled policies and policies whose action or resource type does not match
   are skipped.
2. All other policies are evaluated for a complete audit trail.
3. If any matching deny policy is true, the result is **deny**.
4. Otherwise, if any matching allow policy is true, the result is **allow**.
5. Otherwise, the result is **deny** (default deny).

Policies are ordered by descending `priority`, then by their original order.
The first matching deny wins; if there is no deny, the first matching allow is
reported as determining.

Missing action is denied. If `resource.type` is missing, only policies with a
wildcard (`"*"`) resource type can match.

### Audit trail

```python
decision.evaluations
```

Each `PolicyEvaluation` records:

- `policy_id`
- `effect`
- `scope_matched`
- `condition_result` (`True`, `False`, or `None`)
- `matched`
- `errors`

Errors from missing attributes, type mismatches, invalid dynamic regexes, or
failing custom operators are collected in `decision.errors`.

### Strict indeterminate denies

By default, a deny policy whose condition is indeterminate does not deny.
For stricter environments, use:

```python
engine = Authorizer(policies, indeterminate_deny=True)
```

Then an indeterminate matching deny policy blocks access with a clear reason.
This is safer but can cause outages if policies depend on optional attributes.

## Custom resolvers

Resolvers provide derived attributes without changing the request or the
policy schema. Keys are exact paths or prefixes ending with `.`; the longest
prefix wins.

```python
def expand_roles(request, path):
    roles = set(request["subject"].get("roles", []))
    if "senior_manager" in roles:
        roles.add("manager")
    if "manager" in roles:
        roles.add("employee")
    return sorted(roles)


engine = Authorizer(
    policies,
    resolvers={"subject.effective_roles": expand_roles},
)
```

Then policies can use:

```json
{
  "left": "subject.effective_roles",
  "op": "contains",
  "right": "manager"
}
```

Resolvers are ordinary callables, so they can consult application state,
databases, caches, or an organization graph. Return `MISSING` to fall back to
normal request traversal, and keep them free of side effects if possible.

## Custom operators

Custom operators make arbitrary business logic available to serializable
policies.

```python
def within_budget(left, right, request):
    return left <= right


engine = Authorizer(
    policies,
    operators={"within_budget": within_budget},
)
```

```json
{
  "left": "resource.amount",
  "op": "within_budget",
  "right": 10000
}
```

The signature is `fn(left, right, request) -> bool`. Left and right operands
have already been resolved. Exceptions are treated as indeterminate and
recorded in the decision; they never grant access.

## Business recipes

### Department managers with approval limits

```json
{
  "id": "manager-approve",
  "effect": "allow",
  "actions": ["invoice.approve"],
  "resource_types": ["invoice"],
  "condition": {
    "all": [
      {"left": "subject.roles", "op": "contains", "right": "manager"},
      {
        "left": "resource.department",
        "op": "in",
        "right": {"attr": "subject.departments"}
      },
      {"left": "resource.amount", "op": "<=", "right": 10000}
    ]
  }
}
```

### Cross-department denial with deny-overrides

```json
{
  "id": "deny-cross-department",
  "effect": "deny",
  "actions": ["invoice.*"],
  "resource_types": ["invoice"],
  "condition": {
    "not": {
      "left": "resource.department",
      "op": "in",
      "right": {"attr": "subject.departments"}
    }
  }
}
```

If a manager's allowance also matches, the deny still wins.

### Multiple roles and multiple departments

Use lists in the request and the set-style operators:

```json
{
  "subject": {
    "roles": ["manager", "auditor"],
    "departments": ["finance", "operations"]
  }
}
```

```json
{"left": "subject.roles", "op": "contains", "right": "manager"}
{"left": "subject.departments", "op": "intersects", "right": ["operations", "legal"]}
```

### Tenant isolation

```json
{
  "id": "tenant-document-read",
  "effect": "allow",
  "actions": ["document.read"],
  "resource_types": ["document"],
  "condition": {
    "left": "subject.tenant",
    "op": "==",
    "right": {"attr": "resource.tenant"}
  }
}
```

For hard isolation, pair it with a deny policy or use a strict request builder
that rejects cross-tenant data before authorization.

## Tests and examples

```bash
pytest
python examples/business.py
```

The example covers department managers, approval limits, cross-department
denial, archived records, multi-department membership, and administrators.

## Public API

| Name | Purpose |
| --- | --- |
| `resolve(path, request, resolvers=None)` | Resolve a dot path to a value or `MISSING`. |
| `evaluate_condition(...)` | Evaluate a condition to a bool. |
| `evaluate_condition_outcome(...)` | Evaluate a condition to a three-state result. |
| `validate_condition(...)` | Return condition validation errors. |
| `validate_policies(...)` | Return policy validation errors. |
| `load_policies(...)` | Load and validate policies from dicts. |
| `load_policies_json(...)` | Load and validate policies from JSON text. |
| `load_policies_file(...)` | Load and validate policies from a JSON file. |
| `Authorizer(...)` | Policy decision point. |
| `Policy` | Validated policy object. |
| `Decision` | Authorization result with audit trail. |
| `PolicyEvaluation` | Audit record for one policy. |
| `PolicyValidationError` | Raised for invalid policies. |
| `MISSING` | Sentinel for absent attributes. |

## Limitations and security notes

- Policies are trusted input. Do not let untrusted users author raw policies or
  regular expressions without review. Regex denial-of-service is possible with
  hostile patterns.
- There is no user store, role hierarchy, persistence, CLI, or HTTP service.
  Attributes, role expansion, and data lookup are supplied by the application
  through requests, resolvers, and operators.
- There is no implicit type coercion; `3000` and `"3000"` are different.
- Missing attributes never satisfy ordinary comparisons. Use `exists` and
  `not_exists` when absence is meaningful.
- Default deny and deny-overrides are deliberate defaults for business systems.
- Custom operators and resolvers are application code. Keep them deterministic
  and side-effect free for predictable authorization decisions.
