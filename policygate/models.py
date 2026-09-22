"""领域模型：资源、策略规则、判定结论、豁免、准入记录的类型定义。"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleDecision(str, Enum):
    """单条规则违例时的处置：仅告警 或 拒绝。"""
    WARN = "warn"
    REJECT = "reject"


class OverallDecision(str, Enum):
    """整份资源清单的评估结论。"""
    PASS = "pass"
    WARN = "warn"
    REJECT = "reject"
    EXEMPTED = "exempted"
    ERROR = "error"


class AdmissionAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class RejectReason(str, Enum):
    """彼此可区分的拒绝原因。"""
    POLICY_DOCUMENT_MALFORMED = "policy_document_malformed"
    RULE_SYNTAX_UNSUPPORTED = "rule_syntax_unsupported"
    RESOURCE_FIELD_MISSING = "resource_field_missing"
    POLICY_VIOLATION = "policy_violation"
    EXEMPTION_SCOPE_MISMATCH = "exemption_scope_mismatch"
    EXEMPTION_EXPIRED = "exemption_expired"
    ILLEGAL_STATE_TRANSITION = "illegal_state_transition"
    EXEMPTION_NOT_FOUND = "exemption_not_found"
    RECORD_NOT_FOUND = "record_not_found"
    DUPLICATE_SUBMISSION_CONFLICT = "duplicate_submission_conflict"


class ExemptionStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    REJECTED = "rejected"
    REVOKED = "revoked"


@dataclass(frozen=True)
class Resource:
    uid: str
    api_version: str
    kind: str
    namespace: str
    name: str
    spec: dict[str, object]
    labels: dict[str, str] = field(default_factory=dict)
    raw: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyRule:
    id: str
    description: str
    match_kinds: list[str]
    field_path: str
    operator: str
    expected: object
    severity: Severity
    on_violation: RuleDecision


@dataclass(frozen=True)
class PolicyDocument:
    version: str
    created_at: str
    rules: list[PolicyRule]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    rule_decision: RuleDecision
    message: str
    evidence: str
    exempted_by: str | None = None


@dataclass(frozen=True)
class EvaluationResult:
    resource_uid: str
    resource_fingerprint: str
    policy_version: str
    policy_fingerprint: str
    decision: OverallDecision
    action: AdmissionAction
    findings: list[Finding]
    evaluated_at: str
    replay: bool = False


@dataclass
class Exemption:
    id: str
    rule_ids: list[str] | None
    kinds: list[str] | None
    namespaces: list[str] | None
    resource_uids: list[str] | None
    valid_from: str
    valid_until: str
    reason: str
    status: ExemptionStatus
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class AdmissionRecord:
    idempotency_key: str
    resource_uid: str
    result: EvaluationResult
    created_at: str
