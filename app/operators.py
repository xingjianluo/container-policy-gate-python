"""规则算子实现。

支持：eq / ne / in / not_in / regex / present / absent /
      contains / not_contains / size_lte / size_gte。
- present/absent 只关心字段是否存在，右值被忽略；
- in/not_in/contains 的右值必须是列表；
- regex 的右值必须是合法正则；
未注册算子由解析层提前抛 UnsupportedRuleError，本模块是执行兜底。
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from .errors import UnsupportedRuleError

OperatorFn = Callable[[Any, Any], bool]


def _eq(actual: Any, expected: Any) -> bool:
    return actual == expected


def _ne(actual: Any, expected: Any) -> bool:
    return actual != expected


def _in(actual: Any, expected: Any) -> bool:
    if not isinstance(expected, list):
        raise UnsupportedRuleError(
            "算子 'in' 的右值必须是数组", details={"operator": "in", "value": expected}
        )
    return actual in expected


def _not_in(actual: Any, expected: Any) -> bool:
    if not isinstance(expected, list):
        raise UnsupportedRuleError(
            "算子 'not_in' 的右值必须是数组", details={"operator": "not_in", "value": expected}
        )
    return actual not in expected


def _contains(actual: Any, expected: Any) -> bool:
    if actual is None:
        return False
    try:
        return expected in actual
    except TypeError:
        return False


def _not_contains(actual: Any, expected: Any) -> bool:
    if actual is None:
        return True
    try:
        return expected not in actual
    except TypeError:
        return True


def _regex(actual: Any, expected: Any) -> bool:
    if not isinstance(expected, str) or actual is None:
        return False
    return re.search(expected, str(actual)) is not None


def _present(actual: Any, expected: Any) -> bool:
    return actual is not None


def _absent(actual: Any, expected: Any) -> bool:
    return actual is None


def _size_lte(actual: Any, expected: Any) -> bool:
    try:
        return len(actual) <= expected
    except TypeError:
        return False


def _size_gte(actual: Any, expected: Any) -> bool:
    try:
        return len(actual) >= expected
    except TypeError:
        return False


OPERATORS: dict[str, OperatorFn] = {
    "eq": _eq,
    "ne": _ne,
    "in": _in,
    "not_in": _not_in,
    "regex": _regex,
    "present": _present,
    "absent": _absent,
    "contains": _contains,
    "not_contains": _not_contains,
    "size_lte": _size_lte,
    "size_gte": _size_gte,
}

# 不需要右值的算子
UNARY_OPERATORS = frozenset({"present", "absent"})


def evaluate(operator: str, actual: Any, expected: Any) -> bool:
    """执行算子；未知算子抛 UnsupportedRuleError。

    约定：present/absent 之外，字段不存在（actual is None）一律不满足，
    “必须存在/必须缺失”的语义只能用 present/absent 表达。
    """
    fn = OPERATORS.get(operator)
    if fn is None:
        raise UnsupportedRuleError(
            f"不支持的规则算子: {operator!r}",
            details={"operator": operator, "supported": sorted(OPERATORS)},
        )
    if operator in ("regex",) and isinstance(expected, str):
        try:
            re.compile(expected)
        except re.error as exc:
            raise UnsupportedRuleError(
                f"正则表达式非法: {exc}", details={"operator": "regex", "value": expected}
            ) from exc
    return fn(actual, expected)
