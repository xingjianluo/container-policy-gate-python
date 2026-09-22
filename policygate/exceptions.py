"""领域异常：拒绝原因彼此可区分。"""
from __future__ import annotations

from .models import RejectReason


class GateError(Exception):
    """所有准入服务错误的基类，携带可机器区分的拒绝原因码。"""

    reason: RejectReason

    def __init__(self, reason: RejectReason, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason.value}: {detail}")


class PolicyLoadError(GateError):
    pass


class ResourceValidationError(GateError):
    pass


class ExemptionError(GateError):
    pass


class IllegalTransitionError(GateError):
    pass


class IdempotencyConflictError(GateError):
    pass
