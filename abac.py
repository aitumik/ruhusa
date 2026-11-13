"""Ruhusa: a small, dependency-free Attribute-Based Access Control library.

Policies are plain dictionaries (and therefore JSON-friendly), conditions are
composable data structures, and the decision point applies a deny-overrides
combining algorithm with a default deny.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

__all__ = [
    "ABACError",
    "BUILTIN_OPERATORS",
    "ConditionOutcome",
    "Decision",
    "MISSING",
    "Policy",
    "PolicyEvaluation",
    "PolicyValidationError",
    "UNARY_OPERATORS",
    "Authorizer",
    "evaluate_condition",
    "evaluate_condition_outcome",
    "load_policies",
    "load_policies_file",
    "load_policies_json",
    "resolve",
    "validate_condition",
    "validate_policies",
]


class ABACError(Exception):
    """Base class for Ruhusa errors."""


class PolicyValidationError(ABACError):
    """Raised when policies or conditions are structurally invalid."""

    def __init__(self, errors: Sequence[str]):
        self.errors = tuple(errors)
        super().__init__("; ".join(self.errors) if self.errors else "invalid policy")


class _Missing:
    """Sentinel for an attribute that does not exist."""

    def __eq__(self, other: Any) -> bool:
        return False

    def __ne__(self, other: Any) -> bool:
        return True

    def __repr__(self) -> str:
        return "MISSING"

    __hash__ = None


MISSING = _Missing()

Resolver = Callable[[Mapping[str, Any], str], Any]
Operator = Callable[[Any, Any, Mapping[str, Any]], bool]


def _find_resolver(
    path: str, resolvers: Mapping[str, Resolver]
) -> Optional[Resolver]:
    exact = resolvers.get(path)
    if exact is not None:
        return exact

    best_key: Optional[str] = None
    for key in resolvers:
        if isinstance(key, str) and key.endswith(".") and path.startswith(key):
            if best_key is None or len(key) > len(best_key):
                best_key = key
    if best_key is None:
        return None
    return resolvers[best_key]


def resolve(
    path: str,
    request: Mapping[str, Any],
    resolvers: Optional[Mapping[str, Resolver]] = None,
) -> Any:
    """Resolve a dot path against a request.

    Dict keys are traversed directly. Numeric path segments index into lists and
    tuples. Custom resolvers may provide exact paths or dot-ending prefixes.
    Returns ``MISSING`` when the path cannot be resolved.
    """

    if not isinstance(path, str):
        return MISSING

    if resolvers:
        resolver = _find_resolver(path, resolvers)
        if resolver is not None:
            value = resolver(request, path)
            if value is not MISSING:
                return value

    value: Any = request
    for key in path.split("."):
        if isinstance(value, Mapping):
            if key not in value:
                return MISSING
            value = value[key]
            continue

        if isinstance(value, (list, tuple)):
            try:
                index = int(key)
            except (TypeError, ValueError):
                return MISSING
            try:
                value = value[index]
            except IndexError:
                return MISSING
            continue

        return MISSING

    return value


@dataclass(frozen=True)
class ConditionOutcome:
    """Result of evaluating a condition.

    ``value`` is ``True``, ``False``, or ``None`` for indeterminate. Indeterminate
    means an attribute was missing, an operand had an incompatible type, or an
    operator failed. Indeterminate conditions never grant access.
    """

    value: Optional[bool]
    errors: tuple[str, ...] = ()


def _op_in(left: Any, right: Any, request: Mapping[str, Any]) -> bool:
    if not isinstance(right, (list, tuple, set, frozenset, dict, str)):
        raise TypeError("right operand is not a collection")
    return left in right


def _op_not_in(left: Any, right: Any, request: Mapping[str, Any]) -> bool:
    return not _op_in(left, right, request)


def _op_contains(left: Any, right: Any, request: Mapping[str, Any]) -> bool:
    if not isinstance(left, (list, tuple, set, frozenset, dict, str)):
        raise TypeError("left operand is not a collection")
    return right in left


def _op_not_contains(left: Any, right: Any, request: Mapping[str, Any]) -> bool:
    return not _op_contains(left, right, request)


def _as_collection(value: Any) -> Iterable[Any]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError("operand is not a non-string collection")
    return value


def _op_intersects(left: Any, right: Any, request: Mapping[str, Any]) -> bool:
    left_items = _as_collection(left)
    right_items = list(_as_collection(right))
    return any(item in right_items for item in left_items)


def _op_subset(left: Any, right: Any, request: Mapping[str, Any]) -> bool:
    left_items = _as_collection(left)
    right_items = list(_as_collection(right))
    return all(item in right_items for item in left_items)


def _op_superset(left: Any, right: Any, request: Mapping[str, Any]) -> bool:
    left_items = list(_as_collection(left))
    right_items = _as_collection(right)
    return all(item in left_items for item in right_items)


def _op_startswith(left: Any, right: Any, request: Mapping[str, Any]) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        raise TypeError("operands must be strings")
    return left.startswith(right)


def _op_endswith(left: Any, right: Any, request: Mapping[str, Any]) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        raise TypeError("operands must be strings")
    return left.endswith(right)


def _op_matches(left: Any, right: Any, request: Mapping[str, Any]) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        raise TypeError("operands must be strings")
    return re.fullmatch(right, left) is not None


def _op_exists(left: Any, right: Any, request: Mapping[str, Any]) -> bool:
    return left is not MISSING


def _op_not_exists(left: Any, right: Any, request: Mapping[str, Any]) -> bool:
    return left is MISSING


def _op_is_null(left: Any, right: Any, request: Mapping[str, Any]) -> bool:
    return left is None


def _op_not_null(left: Any, right: Any, request: Mapping[str, Any]) -> bool:
    return left is not None and left is not MISSING


BUILTIN_OPERATORS: dict[str, Operator] = {
    "==": lambda left, right, request: left == right,
    "!=": lambda left, right, request: left != right,
    "<": lambda left, right, request: left < right,
    "<=": lambda left, right, request: left <= right,
    ">": lambda left, right, request: left > right,
    ">=": lambda left, right, request: left >= right,
    "in": _op_in,
    "not_in": _op_not_in,
    "contains": _op_contains,
    "not_contains": _op_not_contains,
    "intersects": _op_intersects,
    "subset": _op_subset,
    "superset": _op_superset,
    "startswith": _op_startswith,
    "endswith": _op_endswith,
    "matches": _op_matches,
    "exists": _op_exists,
    "not_exists": _op_not_exists,
    "is_null": _op_is_null,
    "not_null": _op_not_null,
}

UNARY_OPERATORS = frozenset({"exists", "not_exists", "is_null", "not_null"})


def _merge_operators(
    operators: Optional[Mapping[str, Operator]],
) -> dict[str, Operator]:
    merged = dict(BUILTIN_OPERATORS)
    if operators:
        merged.update(operators)
    return merged


def _operand_label(operand: Any) -> str:
    if isinstance(operand, str):
        return operand
    if isinstance(operand, Mapping) and set(operand) == {"attr"}:
        return str(operand["attr"])
    return "literal value"


def _resolve_operand(
    operand: Any,
    request: Mapping[str, Any],
    resolvers: Mapping[str, Resolver],
    *,
    is_left: bool,
) -> Any:
    if is_left:
        if isinstance(operand, str):
            return resolve(operand, request, resolvers)
        if isinstance(operand, Mapping) and set(operand) == {"attr"}:
            return resolve(operand["attr"], request, resolvers)
        if isinstance(operand, Mapping) and set(operand) == {"value"}:
            return operand["value"]
        return operand

    if isinstance(operand, Mapping) and set(operand) == {"attr"}:
        return resolve(operand["attr"], request, resolvers)
    if isinstance(operand, Mapping) and set(operand) == {"value"}:
        return operand["value"]
    return operand


def _all_states(states: Sequence[Optional[bool]]) -> Optional[bool]:
    if any(state is False for state in states):
        return False
    if any(state is None for state in states):
        return None
    return True


def _any_states(states: Sequence[Optional[bool]]) -> Optional[bool]:
    if any(state is True for state in states):
        return True
    if any(state is None for state in states):
        return None
    return False


def _evaluate_leaf(
    condition: Mapping[str, Any],
    request: Mapping[str, Any],
    resolvers: Mapping[str, Resolver],
    operators: Mapping[str, Operator],
) -> ConditionOutcome:
    op = condition.get("op")
    if not isinstance(op, str):
        return ConditionOutcome(None, ("condition requires a string 'op'",))

    operator = operators.get(op)
    if not callable(operator):
        return ConditionOutcome(None, (f"unknown operator {op!r}",))

    if "left" not in condition:
        return ConditionOutcome(None, (f"operator {op!r} requires a 'left' operand",))

    unary = op in UNARY_OPERATORS
    if not unary and "right" not in condition:
        return ConditionOutcome(None, (f"operator {op!r} requires a 'right' operand",))

    try:
        left = _resolve_operand(
            condition["left"], request, resolvers, is_left=True
        )
        right = (
            None
            if unary
            else _resolve_operand(
                condition["right"], request, resolvers, is_left=False
            )
        )
    except Exception as exc:
        return ConditionOutcome(None, (f"could not resolve operands: {exc}",))

    if not unary:
        if left is MISSING:
            label = _operand_label(condition["left"])
            return ConditionOutcome(
                None, (f"missing attribute {label!r} (left operand)",)
            )
        if right is MISSING:
            label = _operand_label(condition["right"])
            return ConditionOutcome(
                None, (f"missing attribute {label!r} (right operand)",)
            )

    try:
        return ConditionOutcome(bool(operator(left, right, request)), ())
    except Exception as exc:
        return ConditionOutcome(None, (f"operator {op!r} failed: {exc}",))


def _evaluate_condition(
    condition: Any,
    request: Mapping[str, Any],
    resolvers: Mapping[str, Resolver],
    operators: Mapping[str, Operator],
) -> ConditionOutcome:
    if not isinstance(condition, Mapping):
        return ConditionOutcome(None, ("condition must be an object",))

    compound = [name for name in ("all", "any", "not") if name in condition]
    if compound:
        if len(compound) != 1 or set(condition) != {compound[0]}:
            return ConditionOutcome(
                None,
                ("condition must contain exactly one of 'all', 'any', or 'not'",),
            )

        name = compound[0]
        if name == "not":
            inner = condition["not"]
            if not isinstance(inner, Mapping):
                return ConditionOutcome(None, ("'not' requires a condition object",))
            outcome = _evaluate_condition(inner, request, resolvers, operators)
            value = None if outcome.value is None else not outcome.value
            return ConditionOutcome(value, outcome.errors)

        items = condition[name]
        if not isinstance(items, (list, tuple)):
            return ConditionOutcome(
                None, (f"'{name}' requires a list of conditions",)
            )

        outcomes = [
            _evaluate_condition(item, request, resolvers, operators)
            for item in items
        ]
        errors = tuple(error for outcome in outcomes for error in outcome.errors)
        states = [outcome.value for outcome in outcomes]
        value = _all_states(states) if name == "all" else _any_states(states)
        return ConditionOutcome(value, errors)

    return _evaluate_leaf(condition, request, resolvers, operators)


def evaluate_condition_outcome(
    condition: Any,
    request: Mapping[str, Any],
    *,
    resolvers: Optional[Mapping[str, Resolver]] = None,
    operators: Optional[Mapping[str, Operator]] = None,
) -> ConditionOutcome:
    """Evaluate a condition and return its three-state outcome."""

    return _evaluate_condition(
        condition,
        request,
        dict(resolvers or {}),
        _merge_operators(operators),
    )


def evaluate_condition(
    condition: Any,
    request: Mapping[str, Any],
    *,
    resolvers: Optional[Mapping[str, Resolver]] = None,
    operators: Optional[Mapping[str, Operator]] = None,
) -> bool:
    """Evaluate a condition, returning True only when it is definitely true."""

    return evaluate_condition_outcome(
        condition,
        request,
        resolvers=resolvers,
        operators=operators,
    ).value is True


def _valid_path(path: Any) -> bool:
    return (
        isinstance(path, str)
        and bool(path)
        and all(part != "" for part in path.split("."))
    )


def _validate_operand(
    operand: Any,
    *,
    path: str,
    is_left: bool,
    errors: list[str],
) -> None:
    if is_left:
        if isinstance(operand, str):
            if not _valid_path(operand):
                errors.append(f"{path}: invalid attribute path {operand!r}")
            return
        if isinstance(operand, Mapping) and set(operand) == {"attr"}:
            if not _valid_path(operand["attr"]):
                errors.append(f"{path}.attr: invalid attribute path {operand['attr']!r}")
            return
        if isinstance(operand, Mapping) and set(operand) == {"value"}:
            return
        errors.append(
            f"{path}: left operand must be an attribute path, "
            "{'attr': ...}, or {'value': ...}"
        )
        return

    if isinstance(operand, Mapping) and set(operand) == {"attr"}:
        if not _valid_path(operand["attr"]):
            errors.append(f"{path}.attr: invalid attribute path {operand['attr']!r}")


def validate_condition(
    condition: Any,
    *,
    operators: Optional[Mapping[str, Operator]] = None,
    path: str = "condition",
) -> list[str]:
    """Return a list of structural validation errors for a condition."""

    errors: list[str] = []
    registry = _merge_operators(operators) if operators is not None else None
    _validate_condition(
        condition, operators=registry, path=path, errors=errors
    )
    return errors


def _validate_condition(
    condition: Any,
    *,
    operators: Optional[Mapping[str, Operator]],
    path: str,
    errors: list[str],
) -> None:
    if not isinstance(condition, Mapping):
        errors.append(f"{path}: condition must be an object")
        return

    compound = [name for name in ("all", "any", "not") if name in condition]
    if compound:
        if len(compound) != 1 or set(condition) != {compound[0]}:
            errors.append(
                f"{path}: condition must contain exactly one of "
                "'all', 'any', or 'not'"
            )
            return

        name = compound[0]
        if name == "not":
            inner = condition["not"]
            if not isinstance(inner, Mapping):
                errors.append(f"{path}.not: must be a condition object")
                return
            _validate_condition(
                inner, operators=operators, path=f"{path}.not", errors=errors
            )
            return

        items = condition[name]
        if not isinstance(items, (list, tuple)):
            errors.append(f"{path}.{name}: must be a list of conditions")
            return
        for index, item in enumerate(items):
            _validate_condition(
                item,
                operators=operators,
                path=f"{path}.{name}[{index}]",
                errors=errors,
            )
        return

    unknown = set(condition) - {"left", "op", "right"}
    if unknown:
        errors.append(f"{path}: unknown key(s) {sorted(unknown)}")

    if "op" not in condition:
        errors.append(f"{path}: missing 'op'")
        return

    op = condition["op"]
    if not isinstance(op, str):
        errors.append(f"{path}.op: must be a string")
        return

    if operators is not None and op not in operators:
        errors.append(f"{path}.op: unknown operator {op!r}")

    if "left" not in condition:
        errors.append(f"{path}: missing 'left'")
    else:
        _validate_operand(
            condition["left"], path=f"{path}.left", is_left=True, errors=errors
        )

    unary = op in UNARY_OPERATORS
    if unary:
        if "right" in condition:
            errors.append(
                f"{path}: operator {op!r} does not take a 'right' operand"
            )
        return

    if "right" not in condition:
        errors.append(f"{path}: operator {op!r} requires a 'right' operand")
        return

    _validate_operand(
        condition["right"], path=f"{path}.right", is_left=False, errors=errors
    )

    if op != "matches":
        return

    right = condition["right"]
    pattern: Optional[str] = None
    if isinstance(right, str):
        pattern = right
    elif isinstance(right, Mapping) and set(right) == {"value"}:
        if isinstance(right["value"], str):
            pattern = right["value"]
        else:
            errors.append(f"{path}.right: 'matches' requires a string pattern")
    elif isinstance(right, Mapping) and set(right) == {"attr"}:
        return
    else:
        errors.append(f"{path}.right: 'matches' requires a string pattern")

    if pattern is not None:
        try:
            re.compile(pattern)
        except re.error as exc:
            errors.append(f"{path}.right: invalid regular expression: {exc}")


_POLICY_KEYS = {
    "id",
    "effect",
    "actions",
    "resource_types",
    "condition",
    "priority",
    "description",
    "enabled",
    "metadata",
}


def _as_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    return tuple(value)


@dataclass(frozen=True)
class Policy:
    """A single allow or deny policy."""

    id: str
    effect: str
    actions: tuple[str, ...]
    resource_types: tuple[str, ...] = ("*",)
    condition: Optional[Mapping[str, Any]] = None
    priority: int = 0
    description: Optional[str] = None
    enabled: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "actions", _as_tuple(self.actions))
        object.__setattr__(self, "resource_types", _as_tuple(self.resource_types))
        object.__setattr__(self, "metadata", dict(self.metadata or {}))

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id,
            "effect": self.effect,
            "actions": list(self.actions),
            "resource_types": list(self.resource_types),
            "priority": self.priority,
            "enabled": self.enabled,
        }
        if self.condition is not None:
            data["condition"] = self.condition
        if self.description is not None:
            data["description"] = self.description
        if self.metadata:
            data["metadata"] = dict(self.metadata)
        return data


def _normalize_string_list(
    value: Any,
    *,
    path: str,
    errors: list[str],
    required: bool,
) -> tuple[str, ...]:
    if value is None:
        if required:
            errors.append(f"{path}: is required")
        return ("*",)

    if isinstance(value, str):
        if not value:
            errors.append(f"{path}: must be a non-empty string")
        return (value,)

    if isinstance(value, (list, tuple)):
        if not value:
            errors.append(f"{path}: must not be empty")
            return ("*",)
        result: list[str] = []
        for index, item in enumerate(value):
            if not isinstance(item, str) or not item:
                errors.append(
                    f"{path}[{index}]: must be a non-empty string"
                )
            else:
                result.append(item)
        return tuple(result)

    errors.append(f"{path}: must be a string or a list of strings")
    return ("*",)


def _validate_policy_dict(
    data: Any,
    *,
    operators: Optional[Mapping[str, Operator]],
    index: int,
    errors: list[str],
) -> Optional[Policy]:
    path = f"policies[{index}]"
    if not isinstance(data, Mapping):
        errors.append(f"{path}: policy must be an object")
        return None

    unknown = set(data) - _POLICY_KEYS
    if unknown:
        errors.append(f"{path}: unknown key(s) {sorted(unknown)}")

    policy_id = data.get("id")
    if not isinstance(policy_id, str) or not policy_id:
        errors.append(f"{path}.id: must be a non-empty string")

    effect = data.get("effect")
    if effect not in ("allow", "deny"):
        errors.append(f"{path}.effect: must be 'allow' or 'deny'")

    actions = _normalize_string_list(
        data.get("actions"),
        path=f"{path}.actions",
        errors=errors,
        required=True,
    )
    resource_types = _normalize_string_list(
        data.get("resource_types", "*"),
        path=f"{path}.resource_types",
        errors=errors,
        required=False,
    )

    condition = data.get("condition")
    if condition is not None:
        _validate_condition(
            condition,
            operators=operators,
            path=f"{path}.condition",
            errors=errors,
        )

    priority = data.get("priority", 0)
    if isinstance(priority, bool) or not isinstance(priority, int):
        errors.append(f"{path}.priority: must be an integer")
        priority = 0

    description = data.get("description")
    if description is not None and not isinstance(description, str):
        errors.append(f"{path}.description: must be a string")

    enabled = data.get("enabled", True)
    if not isinstance(enabled, bool):
        errors.append(f"{path}.enabled: must be a boolean")
        enabled = True

    metadata = data.get("metadata", {})
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, Mapping):
        errors.append(f"{path}.metadata: must be an object")
        metadata = {}

    if not isinstance(policy_id, str) or not policy_id:
        return None
    if effect not in ("allow", "deny"):
        return None

    return Policy(
        id=policy_id,
        effect=effect,
        actions=actions,
        resource_types=resource_types,
        condition=condition,
        priority=priority,
        description=description,
        enabled=enabled,
        metadata=dict(metadata),
    )


def _unwrap_policies(source: Any) -> list[Any]:
    if isinstance(source, Policy):
        return [source]

    if isinstance(source, Mapping):
        if "policies" in source:
            extra = set(source) - {"policies"}
            if extra:
                raise PolicyValidationError(
                    [f"policies: unknown key(s) {sorted(extra)}"]
                )
            items = source["policies"]
        else:
            items = [source]
    elif isinstance(source, (list, tuple)):
        items = list(source)
    else:
        raise PolicyValidationError(
            [
                "policies must be a list, an object with a 'policies' list, "
                "or a single policy object"
            ]
        )

    if not isinstance(items, (list, tuple)):
        raise PolicyValidationError(["policies: must be a list of policies"])
    return list(items)


def load_policies(
    source: Any,
    *,
    operators: Optional[Mapping[str, Operator]] = None,
) -> list[Policy]:
    """Load and validate policies from dictionaries or Policy objects."""

    items = _unwrap_policies(source)
    errors: list[str] = []
    policies: list[Policy] = []
    registry = _merge_operators(operators) if operators is not None else None

    for index, item in enumerate(items):
        if isinstance(item, Policy):
            item = item.to_dict()
        policy = _validate_policy_dict(
            item, operators=registry, index=index, errors=errors
        )
        if policy is not None:
            policies.append(policy)

    seen: set[str] = set()
    for policy in policies:
        if policy.id in seen:
            errors.append(f"policies: duplicate policy id {policy.id!r}")
        seen.add(policy.id)

    if errors:
        raise PolicyValidationError(errors)
    return policies


def load_policies_json(
    text: str,
    *,
    operators: Optional[Mapping[str, Operator]] = None,
) -> list[Policy]:
    """Load policies from a JSON string."""

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PolicyValidationError([f"invalid JSON: {exc}"]) from exc
    return load_policies(data, operators=operators)


def load_policies_file(
    path: str | Path,
    *,
    operators: Optional[Mapping[str, Operator]] = None,
) -> list[Policy]:
    """Load policies from a JSON file."""

    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyValidationError(
            [f"could not read {file_path}: {exc}"]
        ) from exc
    return load_policies_json(text, operators=operators)


def validate_policies(
    source: Any,
    *,
    operators: Optional[Mapping[str, Operator]] = None,
) -> list[str]:
    """Return validation errors without raising."""

    try:
        load_policies(source, operators=operators)
    except PolicyValidationError as exc:
        return list(exc.errors)
    return []


@dataclass(frozen=True)
class PolicyEvaluation:
    """Audit record for one policy considered during a decision."""

    policy_id: str
    effect: str
    scope_matched: bool
    condition_result: Optional[bool]
    matched: bool
    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class Decision:
    """Authorization decision with an audit trail."""

    allowed: bool
    effect: str
    determining_policy: Optional[str]
    reason: str
    evaluations: tuple[PolicyEvaluation, ...] = ()
    errors: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return self.allowed


def _matches_any(value: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatchcase(value, pattern) for pattern in patterns)


def _scope_match(
    policy: Policy, action: str, resource_type: Optional[str]
) -> bool:
    if not policy.enabled:
        return False
    if not _matches_any(action, policy.actions):
        return False
    if resource_type is None:
        return "*" in policy.resource_types
    return _matches_any(resource_type, policy.resource_types)


class Authorizer:
    """Policy decision point using deny-overrides with a default deny."""

    def __init__(
        self,
        policies: Any,
        *,
        resolvers: Optional[Mapping[str, Resolver]] = None,
        operators: Optional[Mapping[str, Operator]] = None,
        indeterminate_deny: bool = False,
    ):
        merged = dict(BUILTIN_OPERATORS)
        if operators:
            for name, operator in operators.items():
                if not isinstance(name, str) or not name:
                    raise ValueError(
                        "operator names must be non-empty strings"
                    )
                if not callable(operator):
                    raise TypeError(
                        f"operator {name!r} must be callable"
                    )
                merged[name] = operator

        resolver_map = dict(resolvers or {})
        for key, resolver in resolver_map.items():
            if not isinstance(key, str) or not key:
                raise ValueError(
                    "resolver keys must be non-empty strings"
                )
            if not callable(resolver):
                raise TypeError(f"resolver {key!r} must be callable")

        self.operators = merged
        self.resolvers = resolver_map
        self.policies = tuple(load_policies(policies, operators=merged))
        self.indeterminate_deny = bool(indeterminate_deny)

    def authorize(self, request: Mapping[str, Any]) -> Decision:
        """Evaluate a request and return a :class:`Decision`."""

        if not isinstance(request, Mapping):
            raise TypeError("request must be a mapping")

        action = request.get("action")
        if not isinstance(action, str) or not action:
            return Decision(
                allowed=False,
                effect="deny",
                determining_policy=None,
                reason="request is missing a valid 'action'",
            )

        resource = request.get("resource")
        resource_type: Optional[str] = None
        if isinstance(resource, Mapping):
            value = resource.get("type")
            if isinstance(value, str) and value:
                resource_type = value

        ordered = sorted(
            enumerate(self.policies),
            key=lambda pair: (-pair[1].priority, pair[0]),
        )

        evaluations: list[PolicyEvaluation] = []
        for _, policy in ordered:
            scope_matched = _scope_match(policy, action, resource_type)
            if not scope_matched:
                evaluations.append(
                    PolicyEvaluation(
                        policy_id=policy.id,
                        effect=policy.effect,
                        scope_matched=False,
                        condition_result=None,
                        matched=False,
                    )
                )
                continue

            if policy.condition is None:
                outcome = ConditionOutcome(True)
            else:
                outcome = _evaluate_condition(
                    policy.condition,
                    request,
                    self.resolvers,
                    self.operators,
                )

            evaluations.append(
                PolicyEvaluation(
                    policy_id=policy.id,
                    effect=policy.effect,
                    scope_matched=True,
                    condition_result=outcome.value,
                    matched=outcome.value is True,
                    errors=outcome.errors,
                )
            )

        errors = tuple(
            f"{evaluation.policy_id}: {error}"
            for evaluation in evaluations
            for error in evaluation.errors
        )

        deny_match = next(
            (
                evaluation
                for evaluation in evaluations
                if evaluation.scope_matched
                and evaluation.effect == "deny"
                and evaluation.matched
            ),
            None,
        )
        if deny_match is not None:
            return Decision(
                allowed=False,
                effect="deny",
                determining_policy=deny_match.policy_id,
                reason=f"denied by policy {deny_match.policy_id!r}",
                evaluations=tuple(evaluations),
                errors=errors,
            )

        indeterminate_deny_match = next(
            (
                evaluation
                for evaluation in evaluations
                if evaluation.scope_matched
                and evaluation.effect == "deny"
                and evaluation.condition_result is None
            ),
            None,
        )
        if self.indeterminate_deny and indeterminate_deny_match is not None:
            return Decision(
                allowed=False,
                effect="deny",
                determining_policy=indeterminate_deny_match.policy_id,
                reason=(
                    "denied because policy "
                    f"{indeterminate_deny_match.policy_id!r} could not be "
                    "evaluated"
                ),
                evaluations=tuple(evaluations),
                errors=errors,
            )

        allow_match = next(
            (
                evaluation
                for evaluation in evaluations
                if evaluation.scope_matched
                and evaluation.effect == "allow"
                and evaluation.matched
            ),
            None,
        )
        if allow_match is not None:
            return Decision(
                allowed=True,
                effect="allow",
                determining_policy=allow_match.policy_id,
                reason=f"allowed by policy {allow_match.policy_id!r}",
                evaluations=tuple(evaluations),
                errors=errors,
            )

        return Decision(
            allowed=False,
            effect="deny",
            determining_policy=None,
            reason="no matching allow policy (default deny)",
            evaluations=tuple(evaluations),
            errors=errors,
        )

    def is_allowed(self, request: Mapping[str, Any]) -> bool:
        """Return only the boolean decision."""

        return self.authorize(request).allowed
