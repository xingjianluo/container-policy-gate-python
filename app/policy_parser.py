"""策略文档解析与校验（JSON 格式，仅依赖标准库）。

明确区分两类失败，绝不让畸形策略静默变成“无规则可匹配 -> 放行”：
- PolicyDocumentError：文档结构/格式错误
  （JSON 无法解析、根节点非对象、缺 name/version/rules、类型错、
    规则缺 id/field/operator、severity/on_violation 取值非法、规则 id 重复）；
- UnsupportedRuleError：文档结构合法，但规则语法不受支持
  （未知算子、算子右值类型/语法非法）。
"""

from __future__ import annotations

import json
from typing import Any

from .errors import PolicyDocumentError, UnsupportedRuleError
from .models import Rule, Severity
from .operators import OPERATORS, UNARY_OPERATORS

SUPPORTED_OPERATORS: frozenset[str] = frozenset(OPERATORS)
_VALID_MATCH_KEYS = frozenset({"kind", "apiVersion", "namespace", "name", "labels"})
_VALID_ON_VIOLATION = frozenset({"deny", "warn"})


def parse_document(raw: str | bytes | dict[str, Any]) -> tuple[str, int, tuple[Rule, ...], str]:
    """解析原始策略文档，返回 (name, version, rules, description)。"""
    doc = _coerce_document(raw)

    name = doc.get("name")
    if not isinstance(name, str) or not name.strip():
        raise PolicyDocumentError(
            "策略文档缺少合法的 'name'（非空字符串）", details={"actual": name}
        )

    version = doc.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise PolicyDocumentError(
            "策略文档缺少合法的 'version'（>=1 的整数）", details={"actual": version}
        )

    description = doc.get("description", "")
    if not isinstance(description, str):
        raise PolicyDocumentError("'description' 必须是字符串", details={"actual": description})

    rules_raw = doc.get("rules")
    if not isinstance(rules_raw, list):
        raise PolicyDocumentError(
            "策略文档缺少合法的 'rules'（数组）",
            {"actual_type": type(rules_raw).__name__},
        )

    rules: list[Rule] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(rules_raw):
        rule = _parse_rule(item, index)
        if rule.id in seen_ids:
            raise PolicyDocumentError(
                f"规则 id 重复: {rule.id}", details={"rule_id": rule.id}
            )
        seen_ids.add(rule.id)
        rules.append(rule)

    return name.strip(), version, tuple(rules), description


def _coerce_document(raw: str | bytes | dict[str, Any]) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, (str, bytes)):
        try:
            doc = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise PolicyDocumentError(
                f"策略文档不是合法 JSON: {exc}", details={"position": getattr(exc, "pos", None)}
            ) from exc
        if not isinstance(doc, dict):
            raise PolicyDocumentError(
                "策略文档根节点必须是 JSON 对象", details={"actual_type": type(doc).__name__}
            )
        return doc
    raise PolicyDocumentError(
        "策略文档必须是 JSON 对象或 JSON 字符串",
        details={"actual_type": type(raw).__name__},
    )


def _parse_rule(raw: Any, index: int) -> Rule:
    where = f"rules[{index}]"
    if not isinstance(raw, dict):
        raise PolicyDocumentError(f"{where} 必须是对象", {"actual_type": type(raw).__name__})

    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise PolicyDocumentError(f"{where}.id 必须是非空字符串", {"actual": rule_id})

    description = raw.get("description", "")
    if not isinstance(description, str):
        raise PolicyDocumentError(f"{where}.description 必须是字符串", {"rule_id": rule_id})

    field = raw.get("field")
    if not isinstance(field, str) or not field.strip():
        raise PolicyDocumentError(f"{where}.field 必须是非空字符串", {"rule_id": rule_id})
    _validate_field_path(field, rule_id)

    operator = raw.get("operator")
    if not isinstance(operator, str) or not operator.strip():
        raise PolicyDocumentError(f"{where}.operator 必须是非空字符串", {"rule_id": rule_id})

    # 文档结构合法，但算子不受支持 —— 与文档格式错误明确区分
    if operator not in SUPPORTED_OPERATORS:
        raise UnsupportedRuleError(
            f"规则 {rule_id} 使用了不支持的算子: {operator!r}",
            {
                "rule_id": rule_id,
                "operator": operator,
                "supported": sorted(SUPPORTED_OPERATORS),
            },
        )

    has_value = "value" in raw
    if operator in UNARY_OPERATORS:
        value = raw.get("value")  # 允许携带但忽略
    elif not has_value:
        raise UnsupportedRuleError(
            f"规则 {rule_id} 的算子 {operator!r} 缺少右值 'value'",
            {"rule_id": rule_id, "operator": operator},
        )
    else:
        value = raw["value"]
        _validate_operand(rule_id, operator, value)

    match = raw.get("match", {})
    _validate_match(match, rule_id)

    severity = _parse_severity(raw.get("severity", "medium"), rule_id)

    on_violation = raw.get("on_violation", "deny")
    if on_violation not in _VALID_ON_VIOLATION:
        raise PolicyDocumentError(
            f"规则 {rule_id} 的 on_violation 非法: {on_violation!r}（允许 deny/warn）",
            {"rule_id": rule_id, "actual": on_violation},
        )

    return Rule(
        id=rule_id.strip(),
        description=description,
        match=match,
        field=field.strip(),
        operator=operator,
        value=value,
        severity=severity,
        on_violation=on_violation,
    )


def _validate_field_path(path: str, rule_id: str) -> None:
    """校验点分路径：标识符键或数字下标，空段/非法段报规则语法错误。"""
    for part in path.strip().split("."):
        if not part:
            raise PolicyDocumentError(
                f"规则 {rule_id} 的 field 路径含空段: {path!r}", {"rule_id": rule_id}
            )
        if not (part.isidentifier() or part.isdigit()):
            raise UnsupportedRuleError(
                f"规则 {rule_id} 的 field 段 {part!r} 语法不受支持"
                "（支持点分键名与数字下标）",
                {"rule_id": rule_id, "segment": part},
            )


def _validate_operand(rule_id: str, operator: str, value: Any) -> None:
    if operator in ("in", "not_in") and not isinstance(value, list):
        raise UnsupportedRuleError(
            f"规则 {rule_id} 的算子 {operator!r} 右值必须是数组",
            {"rule_id": rule_id, "operator": operator, "value_type": type(value).__name__},
        )
    if operator == "regex":
        if not isinstance(value, str):
            raise UnsupportedRuleError(
                f"规则 {rule_id} 的 'regex' 右值必须是字符串",
                {"rule_id": rule_id, "value_type": type(value).__name__},
            )
        import re

        try:
            re.compile(value)
        except re.error as exc:
            raise UnsupportedRuleError(
                f"规则 {rule_id} 的正则表达式非法: {exc}",
                {"rule_id": rule_id, "value": value},
            ) from exc
    if operator in ("size_lte", "size_gte") and (
        isinstance(value, bool) or not isinstance(value, int)
    ):
        raise UnsupportedRuleError(
            f"规则 {rule_id} 的算子 {operator!r} 右值必须是整数",
            {"rule_id": rule_id, "operator": operator, "actual_type": type(value).__name__},
        )


def _validate_match(match: Any, rule_id: str) -> None:
    if match is None:
        return
    if not isinstance(match, dict):
        raise PolicyDocumentError(
            f"规则 {rule_id} 的 match 必须是对象", {"rule_id": rule_id}
        )
    unknown = set(match) - _VALID_MATCH_KEYS
    if unknown:
        raise PolicyDocumentError(
            f"规则 {rule_id} 的 match 含未知键: {sorted(unknown)}",
            {"rule_id": rule_id, "unknown": sorted(unknown)},
        )
    labels = match.get("labels")
    if labels is not None and (
        not isinstance(labels, dict)
        or not all(isinstance(k, str) and isinstance(v, str) for k, v in labels.items())
    ):
        raise PolicyDocumentError(
            f"规则 {rule_id} 的 match.labels 必须是 字符串->字符串 的对象",
            {"rule_id": rule_id},
        )


def _parse_severity(value: Any, rule_id: str) -> Severity:
    if not isinstance(value, str):
        raise PolicyDocumentError(
            f"规则 {rule_id} 的 severity 必须是字符串", {"rule_id": rule_id, "actual": value}
        )
    try:
        return Severity(value)
    except ValueError:
        raise PolicyDocumentError(
            f"规则 {rule_id} 的 severity 非法: {value!r}",
            {
                "rule_id": rule_id,
                "actual": value,
                "allowed": [s.value for s in Severity],
            },
        ) from None
