"""策略存储：从本地目录加载多版本策略。

设计要点：
- 每个策略文件为 ``policy-<version>.json``，文档内 ``version`` 必须与文件名一致；
- 版本一旦落盘即不可变：存储只读取，不提供修改/删除；
- 加载时严格校验，两类失败严格区分：
  * 文档结构/JSON/枚举错误 -> POLICY_DOCUMENT_MALFORMED
  * 操作符/字段路径/操作数等"规则语法"错误 -> RULE_SYNTAX_UNSUPPORTED
"""
from __future__ import annotations

import json
import os
import re

from .exceptions import PolicyLoadError
from .fingerprints import sha256_fingerprint
from .models import PolicyDocument, PolicyRule, RejectReason, RuleDecision, Severity

# 评估引擎支持的全部规则操作符；解析期与评估期共用同一份集合。
SUPPORTED_OPERATORS = frozenset(
    {
        "equals",
        "not_equals",
        "in",
        "not_in",
        "exists",
        "not_exists",
        "regex",
        "less_than",
        "greater_than",
    }
)

_NO_OPERAND = frozenset({"exists", "not_exists"})
_LIST_OPERAND = frozenset({"in", "not_in"})
_NUM_OPERAND = frozenset({"less_than", "greater_than"})
_SCALAR_OPERAND = frozenset({"equals", "not_equals"})
_REGEX_OPERAND = frozenset({"regex"})

_FIELD_PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
_FILENAME_RE = re.compile(r"^policy-(?P<version>.+)\.json$")


def _version_sort_key(version: str) -> tuple:
    """支持 v1 / v1.2 / 10 等形式的自然排序：按点分段，数字段按整数比较。"""
    raw = version[1:] if version.startswith("v") else version
    parts: list[object] = []
    for segment in raw.split("."):
        if segment.isdigit():
            parts.append((0, int(segment)))
        else:
            parts.append((1, segment))
    return tuple(parts)


class PolicyStore:
    def __init__(self, policy_dir: str) -> None:
        self._dir = policy_dir
        self._documents: dict[str, PolicyDocument] = {}
        self._fingerprints: dict[str, str] = {}
        self._load_all()

    def _load_all(self) -> None:
        if not os.path.isdir(self._dir):
            raise PolicyLoadError(
                RejectReason.POLICY_DOCUMENT_MALFORMED,
                f"策略目录不存在: {self._dir}",
            )
        for name in sorted(os.listdir(self._dir)):
            if not name.endswith(".json"):
                continue
            match = _FILENAME_RE.match(name)
            if not match:
                raise PolicyLoadError(
                    RejectReason.POLICY_DOCUMENT_MALFORMED,
                    f"策略文件名不符合 policy-<version>.json: {name}",
                )
            path = os.path.join(self._dir, name)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                raise PolicyLoadError(
                    RejectReason.POLICY_DOCUMENT_MALFORMED,
                    f"{name} 不是合法 JSON: {exc}",
                ) from exc
            version, doc = self._parse_document(name, match.group("version"), data)
            if version in self._documents:
                raise PolicyLoadError(
                    RejectReason.POLICY_DOCUMENT_MALFORMED,
                    f"策略版本重复: {version}",
                )
            self._documents[version] = doc
            self._fingerprints[version] = sha256_fingerprint(
                {
                    "version": doc.version,
                    "created_at": doc.created_at,
                    "rules": [
                        {
                            "id": r.id,
                            "description": r.description,
                            "match_kinds": r.match_kinds,
                            "field_path": r.field_path,
                            "operator": r.operator,
                            "expected": r.expected,
                            "severity": r.severity.value,
                            "on_violation": r.on_violation.value,
                        }
                        for r in doc.rules
                    ],
                }
            )

    def _parse_document(
        self, filename: str, file_version: str, data: object
    ) -> tuple[str, PolicyDocument]:
        if not isinstance(data, dict):
            raise PolicyLoadError(
                RejectReason.POLICY_DOCUMENT_MALFORMED,
                f"{filename} 顶层必须是 JSON 对象",
            )
        version = data.get("version")
        if not isinstance(version, str) or not version:
            raise PolicyLoadError(
                RejectReason.POLICY_DOCUMENT_MALFORMED,
                f"{filename} 缺少字符串字段 version",
            )
        if version != file_version:
            raise PolicyLoadError(
                RejectReason.POLICY_DOCUMENT_MALFORMED,
                f"{filename} 文件名版本 {file_version} 与文档版本 {version} 不一致",
            )
        created_at = data.get("created_at")
        if not isinstance(created_at, str) or not created_at:
            raise PolicyLoadError(
                RejectReason.POLICY_DOCUMENT_MALFORMED,
                f"{filename} 缺少字符串字段 created_at",
            )
        rules_data = data.get("rules")
        if not isinstance(rules_data, list):
            raise PolicyLoadError(
                RejectReason.POLICY_DOCUMENT_MALFORMED,
                f"{filename} 的 rules 必须是数组",
            )
        rules = [self._parse_rule(filename, item) for item in rules_data]
        seen: set[str] = set()
        for rule in rules:
            if rule.id in seen:
                raise PolicyLoadError(
                    RejectReason.POLICY_DOCUMENT_MALFORMED,
                    f"{filename} 规则 id 重复: {rule.id}",
                )
            seen.add(rule.id)
        return version, PolicyDocument(
            version=version, created_at=created_at, rules=rules
        )

    def _parse_rule(self, filename: str, item: object) -> PolicyRule:
        if not isinstance(item, dict):
            raise PolicyLoadError(
                RejectReason.POLICY_DOCUMENT_MALFORMED,
                f"{filename} 每条规则必须是 JSON 对象",
            )
        required = ("id", "description", "match_kinds", "field_path",
                    "operator", "severity", "on_violation")
        for key in required:
            if key not in item:
                raise PolicyLoadError(
                    RejectReason.POLICY_DOCUMENT_MALFORMED,
                    f"{filename} 规则缺少字段 {key}: {item!r}",
                )
        rid = item["id"]
        if not isinstance(rid, str) or not rid:
            raise PolicyLoadError(
                RejectReason.POLICY_DOCUMENT_MALFORMED,
                f"{filename} 规则 id 必须是非空字符串",
            )
        description = item["description"]
        if not isinstance(description, str):
            raise PolicyLoadError(
                RejectReason.POLICY_DOCUMENT_MALFORMED,
                f"{filename} 规则 {rid} 的 description 必须是字符串",
            )
        match_kinds = item["match_kinds"]
        if (
            not isinstance(match_kinds, list)
            or not match_kinds
            or not all(isinstance(k, str) and k for k in match_kinds)
        ):
            raise PolicyLoadError(
                RejectReason.POLICY_DOCUMENT_MALFORMED,
                f"{filename} 规则 {rid} 的 match_kinds 必须是非空字符串数组",
            )
        field_path = item["field_path"]
        if not isinstance(field_path, str) or not _FIELD_PATH_RE.match(field_path):
            raise PolicyLoadError(
                RejectReason.RULE_SYNTAX_UNSUPPORTED,
                f"{filename} 规则 {rid} 的 field_path 语法不支持: {field_path!r}",
            )
        operator = item["operator"]
        if not isinstance(operator, str) or operator not in SUPPORTED_OPERATORS:
            raise PolicyLoadError(
                RejectReason.RULE_SYNTAX_UNSUPPORTED,
                f"{filename} 规则 {rid} 使用了不支持的操作符: {operator!r}",
            )
        expected = item.get("expected", None)
        self._validate_operand(filename, rid, operator, expected)
        try:
            severity = Severity(item["severity"])
        except ValueError as exc:
            raise PolicyLoadError(
                RejectReason.POLICY_DOCUMENT_MALFORMED,
                f"{filename} 规则 {rid} 的 severity 非法: {item['severity']!r}",
            ) from exc
        try:
            on_violation = RuleDecision(item["on_violation"])
        except ValueError as exc:
            raise PolicyLoadError(
                RejectReason.POLICY_DOCUMENT_MALFORMED,
                f"{filename} 规则 {rid} 的 on_violation 非法: {item['on_violation']!r}",
            ) from exc
        return PolicyRule(
            id=rid,
            description=description,
            match_kinds=list(match_kinds),
            field_path=field_path,
            operator=operator,
            expected=expected,
            severity=severity,
            on_violation=on_violation,
        )

    @staticmethod
    def _validate_operand(filename: str, rid: str, operator: str, expected: object) -> None:
        if operator in _NO_OPERAND:
            return
        if operator in _LIST_OPERAND:
            if not isinstance(expected, list) or not expected:
                raise PolicyLoadError(
                    RejectReason.RULE_SYNTAX_UNSUPPORTED,
                    f"{filename} 规则 {rid} 操作符 {operator} 需要非空数组 expected",
                )
            return
        if operator in _NUM_OPERAND:
            if isinstance(expected, bool) or not isinstance(expected, (int, float)):
                raise PolicyLoadError(
                    RejectReason.RULE_SYNTAX_UNSUPPORTED,
                    f"{filename} 规则 {rid} 操作符 {operator} 需要数值 expected",
                )
            return
        if operator in _SCALAR_OPERAND:
            if not isinstance(expected, (str, bool, int, float)):
                raise PolicyLoadError(
                    RejectReason.RULE_SYNTAX_UNSUPPORTED,
                    f"{filename} 规则 {rid} 操作符 {operator} 需要标量 expected（字符串/数值/布尔）",
                )
            return
        if operator in _REGEX_OPERAND:
            if not isinstance(expected, str):
                raise PolicyLoadError(
                    RejectReason.RULE_SYNTAX_UNSUPPORTED,
                    f"{filename} 规则 {rid} 操作符 {operator} 需要字符串 expected",
                )
            try:
                re.compile(expected)
            except re.error as exc:
                raise PolicyLoadError(
                    RejectReason.RULE_SYNTAX_UNSUPPORTED,
                    f"{filename} 规则 {rid} 的正则无法编译: {exc}",
                ) from exc

    def latest_version(self) -> str:
        if not self._documents:
            raise PolicyLoadError(
                RejectReason.POLICY_DOCUMENT_MALFORMED,
                f"策略目录中没有任何策略文件: {self._dir}",
            )
        return max(self._documents, key=_version_sort_key)

    def get(self, version: str) -> PolicyDocument:
        try:
            return self._documents[version]
        except KeyError:
            raise PolicyLoadError(
                RejectReason.POLICY_DOCUMENT_MALFORMED,
                f"策略版本不存在: {version}",
            ) from None

    def fingerprint_of(self, version: str) -> str:
        if version not in self._fingerprints:
            raise PolicyLoadError(
                RejectReason.POLICY_DOCUMENT_MALFORMED,
                f"策略版本不存在: {version}",
            )
        return self._fingerprints[version]

    def all_versions(self) -> list[str]:
        return sorted(self._documents, key=_version_sort_key)
