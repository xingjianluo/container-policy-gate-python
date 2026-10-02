"""领域模型：严重级别、处置结果、规则、判定、豁免等。

严重级别（severity）描述规则的严厉程度，处置结果（action）描述
准入系统对资源采取的动作，二者刻意分离：
例如 HIGH 严重级别的规则命中后可以 deny，被豁免时又可降级为 allow_with_warning。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """规则严重级别。"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(str, Enum):
    """对单条规则的判定结论。"""

    PASS = "pass"        # 规则通过（条件不命中）
    VIOLATION = "violation"  # 规则命中且构成违规
    SKIPPED = "skipped"  # 规则未参与判定（如不适用）


class Action(str, Enum):
    """准入处置结果（与严重级别可区分）。"""

    ALLOW = "allow"
    ALLOW_WITH_WARNING = "allow_with_warning"  # 命中但被豁免
    DENY = "deny"


# 资源清单必填字段
REQUIRED_RESOURCE_FIELDS = ("apiVersion", "kind", "metadata", "spec")


@dataclass(frozen=True)
class Rule:
    """一条策略规则。

    match: 资源选择器（kind / namespace / labels / name 等）
    field: 被检查的资源字段路径（点分）
    operator: 算子，如 eq/ne/in/not_in/regex/present/absent
    value: 算子右值
    severity: 严重级别
    on_violation: 命中时的处置（deny / warn）
    """

    id: str
    description: str
    match: dict[str, Any]
    field: str
    operator: str
    value: Any
    severity: Severity
    on_violation: str = "deny"


@dataclass(frozen=True)
class Policy:
    """一个不可变策略版本。"""

    name: str
    version: int
    fingerprint: str
    rules: tuple[Rule, ...] = field(default_factory=tuple)
    created_at: str = ""
    description: str = ""


@dataclass(frozen=True)
class RuleHit:
    """单条规则的判定依据。"""

    rule_id: str
    verdict: Verdict
    severity: Severity
    field: str
    operator: str
    expected: Any
    actual: Any
    reason: str
    exempted: bool = False
    exemption_id: str | None = None


@dataclass(frozen=True)
class Decision:
    """一次准入判定的完整结论（不可变、可复现）。"""

    decision_id: str
    idempotency_key: str | None
    resource_ref: str
    resource_fingerprint: str
    policy_name: str
    policy_version: int
    policy_fingerprint: str
    action: Action
    hits: tuple[RuleHit, ...]
    rationale: str
    decided_at: str


# 批量条目状态
BATCH_ITEM_DECIDED = "decided"  # 正常出判定结论
BATCH_ITEM_INVALID = "invalid"  # 资源清单不合法，单独标记，不影响整批


@dataclass(frozen=True)
class BatchItemResult:
    """批量准入中单个资源的结论。

    status=decided 时 decision 非空；status=invalid 时 error 非空。
    reused=True 表示复用了同内容同策略版本的既有判定，未产生新记录。
    """

    index: int
    status: str
    resource_ref: str | None
    decision: Decision | None
    reused: bool
    error: dict[str, Any] | None


@dataclass(frozen=True)
class BatchSummary:
    """整批汇总结论（只含计数与整体处置，与条目提交顺序无关）。"""

    total: int
    decided: int
    invalid: int
    allow: int
    allow_with_warning: int
    deny: int
    action: Action
    rationale: str


@dataclass(frozen=True)
class BatchResult:
    """一次批量准入的完整结论（不可变、可复现）。

    batch_fingerprint 由排序后的条目内容指纹计算，
    同一批资源换序提交得到同一批次标识与汇总。
    """

    batch_id: str
    batch_fingerprint: str
    policy_name: str
    policy_version: int
    policy_fingerprint: str
    summary: BatchSummary
    items: tuple[BatchItemResult, ...]
    created_at: str
    reused: bool = False
