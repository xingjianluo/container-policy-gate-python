"""可区分的错误类型。

每类错误对应稳定的 ``code``，HTTP 层据此映射状态码，
保证“畸形策略 / 不支持的规则语法 / 必填字段缺失 / 豁免越界 / 状态非法流转”
等拒绝原因彼此可区分，绝不静默放行。
"""

from __future__ import annotations


class GateError(Exception):
    """所有业务错误的基类。"""

    code: str = "gate_error"
    http_status: int = 400

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict:
        return {"error": self.code, "message": self.message, "details": self.details}


class PolicyDocumentError(GateError):
    """策略文档格式错误（无法解析 / 结构不合法）。"""

    code = "policy_document_invalid"
    http_status = 422


class UnsupportedRuleError(GateError):
    """规则语法/算子不受支持。"""

    code = "unsupported_rule_syntax"
    http_status = 422


class ResourceValidationError(GateError):
    """资源清单必填字段缺失或类型不合法。"""

    code = "resource_validation_failed"
    http_status = 422


class PolicyVersionConflict(GateError):
    """策略版本冲突（版本号未递增/并发覆盖）。"""

    code = "policy_version_conflict"
    http_status = 409


class ExemptionNotFound(GateError):
    """豁免不存在。"""

    code = "exemption_not_found"
    http_status = 404


class NotFound(GateError):
    """通用资源不存在（策略/判定记录等）。"""

    code = "not_found"
    http_status = 404


class ExemptionOutOfScope(GateError):
    """豁免不在生效范围内（资源不匹配）。"""

    code = "exemption_out_of_scope"
    http_status = 422


class ExemptionExpired(GateError):
    """豁免已过期或尚未生效。"""

    code = "exemption_expired"
    http_status = 422


class IllegalStateTransition(GateError):
    """非法的豁免状态流转。"""

    code = "illegal_state_transition"
    http_status = 409


class DuplicateSubmission(GateError):
    """重复提交（幂等键已有确定结果）。"""

    code = "duplicate_submission"
    http_status = 409


class StorageError(GateError):
    """持久化层错误。"""

    code = "storage_error"
    http_status = 500
