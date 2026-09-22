r"""豁免领域服务：生效范围 + 有效期 + 状态机 + 幂等。

状态机：requested -> approved -> (revoked)
                 \-> rejected
非法流转抛 IllegalStateTransition。
范围越界抛 ExemptionOutOfScope，过期抛 ExemptionExpired，二者可区分。

scope 支持 kind/apiVersion/namespace/name/labels，语义与规则 match 相同；
空 scope 表示对所有资源生效（仅建议在测试中使用）。
rule_ids 为空表示豁免该资源命中的全部规则。
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .clock import Clock, parse_iso, to_iso
from .errors import (
    ExemptionExpired,
    ExemptionNotFound,
    ExemptionOutOfScope,
    IllegalStateTransition,
    PolicyDocumentError,
)
from .resource import resource_matches
from .storage import JsonStore

_DEFAULT_DATA: dict[str, Any] = {"exemptions": {}, "idempotency": {}}
_VALID_SCOPE_KEYS = frozenset({"kind", "apiVersion", "namespace", "name", "labels"})


class ExemptionStatus(str, Enum):
    REQUESTED = "requested"
    APPROVED = "approved"
    REJECTED = "rejected"
    REVOKED = "revoked"


ALLOWED_TRANSITIONS: dict[ExemptionStatus, frozenset[ExemptionStatus]] = {
    ExemptionStatus.REQUESTED: frozenset(
        {ExemptionStatus.APPROVED, ExemptionStatus.REJECTED}
    ),
    ExemptionStatus.APPROVED: frozenset({ExemptionStatus.REVOKED}),
    ExemptionStatus.REJECTED: frozenset(),
    ExemptionStatus.REVOKED: frozenset(),
}


@dataclass(frozen=True)
class Exemption:
    exemption_id: str
    idempotency_key: str | None
    scope: dict[str, Any]
    rule_ids: tuple[str, ...]
    valid_from: str
    valid_until: str
    reason: str
    status: ExemptionStatus
    requested_at: str
    decided_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "exemption_id": self.exemption_id,
            "idempotency_key": self.idempotency_key,
            "scope": self.scope,
            "rule_ids": list(self.rule_ids),
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "reason": self.reason,
            "status": self.status.value,
            "requested_at": self.requested_at,
            "decided_at": self.decided_at,
        }


class ExemptionService:
    """豁免管理服务。"""

    def __init__(self, store: JsonStore, clock: Clock) -> None:
        self._store = store
        self._clock = clock

    # ---- 申请 / 状态流转 ----

    def request(self, payload: dict[str, Any]) -> Exemption:
        """提交豁免申请（按 idempotency_key 幂等）。"""
        scope, rule_ids, valid_from, valid_until, reason, idem_key = self._validate_payload(
            payload
        )
        now_iso = to_iso(self._clock.now())

        with self._store.mutate() as data:
            if idem_key is not None:
                existing_id = data.setdefault("idempotency", {}).get(
                    self._idem_namespace(idem_key)
                )
                if existing_id is not None:
                    return self._to_model(data["exemptions"][existing_id])
            exemption_id = uuid.uuid4().hex
            record = {
                "exemption_id": exemption_id,
                "idempotency_key": idem_key,
                "scope": scope,
                "rule_ids": list(rule_ids),
                "valid_from": to_iso(valid_from),
                "valid_until": to_iso(valid_until),
                "reason": reason,
                "status": ExemptionStatus.REQUESTED.value,
                "requested_at": now_iso,
                "decided_at": None,
            }
            data.setdefault("exemptions", {})[exemption_id] = record
            if idem_key is not None:
                data.setdefault("idempotency", {})[self._idem_namespace(idem_key)] = exemption_id
            return self._to_model(record)

    def approve(self, exemption_id: str) -> Exemption:
        return self._transition(exemption_id, ExemptionStatus.APPROVED)

    def reject(self, exemption_id: str) -> Exemption:
        return self._transition(exemption_id, ExemptionStatus.REJECTED)

    def revoke(self, exemption_id: str) -> Exemption:
        return self._transition(exemption_id, ExemptionStatus.REVOKED)

    def get(self, exemption_id: str) -> Exemption:
        data = self._store.load()
        record = data.get("exemptions", {}).get(exemption_id)
        if record is None:
            raise ExemptionNotFound(f"豁免不存在: {exemption_id}")
        return self._to_model(record)

    def lookup_idempotency(self, key: str) -> str | None:
        """按幂等键查既有豁免 ID；无则 None。"""
        data = self._store.load()
        return data.get("idempotency", {}).get(self._idem_namespace(key))

    # ---- 准入时使用 ----

    def applicable(self, resource: dict[str, Any], rule_id: str, at: Any) -> list[Exemption]:
        """返回在 ``at`` 时刻对 该资源+该规则 有效的已批准豁免。

        - 只看 approved 状态；
        - 范围不匹配/规则不在 rule_ids/不在有效期 => 不返回（调用方据此拒绝采纳）；
        - 本方法做“过滤”，范围或时间的显式校验由 check_* 抛出可区分错误。
        """
        from datetime import datetime

        moment = at if isinstance(at, datetime) else parse_iso(at)
        result: list[Exemption] = []
        data = self._store.load()
        for record in data.get("exemptions", {}).values():
            model = self._to_model(record)
            if model.status is not ExemptionStatus.APPROVED:
                continue
            if not self._time_valid(model, moment):
                continue
            if not self._covers(model, resource, rule_id):
                continue
            result.append(model)
        return result

    def check_adoption(
        self, exemption_id: str, resource: dict[str, Any], rule_id: str, at: Any
    ) -> Exemption:
        """显式校验某条豁免能否被采纳；范围/时间错误分别抛出可区分异常。"""
        from datetime import datetime

        model = self.get(exemption_id)
        moment = at if isinstance(at, datetime) else parse_iso(at)
        if model.status is not ExemptionStatus.APPROVED:
            raise IllegalStateTransition(
                f"豁免 {exemption_id} 当前状态 {model.status.value}，未批准的豁免不得采纳",
                {"exemption_id": exemption_id, "status": model.status.value},
            )
        if not self._time_valid(model, moment):
            raise ExemptionExpired(
                f"豁免 {exemption_id} 不在有效期内 "
                f"({model.valid_from} ~ {model.valid_until})，判定时刻 {to_iso(moment)}",
                {
                    "exemption_id": exemption_id,
                    "valid_from": model.valid_from,
                    "valid_until": model.valid_until,
                    "at": to_iso(moment),
                },
            )
        if not self._covers(model, resource, rule_id):
            raise ExemptionOutOfScope(
                f"豁免 {exemption_id} 的生效范围不覆盖 {rule_id} 或该资源",
                {"exemption_id": exemption_id, "rule_id": rule_id},
            )
        return model

    # ---- internal ----

    def _transition(self, exemption_id: str, target: ExemptionStatus) -> Exemption:
        with self._store.mutate() as data:
            record = data.get("exemptions", {}).get(exemption_id)
            if record is None:
                raise ExemptionNotFound(f"豁免不存在: {exemption_id}")
            current = ExemptionStatus(record["status"])
            if target not in ALLOWED_TRANSITIONS[current]:
                raise IllegalStateTransition(
                    f"非法状态流转: {current.value} -> {target.value}",
                    {
                        "exemption_id": exemption_id,
                        "from": current.value,
                        "to": target.value,
                        "allowed": sorted(s.value for s in ALLOWED_TRANSITIONS[current]),
                    },
                )
            record["status"] = target.value
            record["decided_at"] = to_iso(self._clock.now())
            return self._to_model(record)

    @staticmethod
    def _idem_namespace(key: str) -> str:
        return f"exemption_request:{key}"

    @staticmethod
    def _covers(model: Exemption, resource: dict[str, Any], rule_id: str) -> bool:
        if model.rule_ids and rule_id not in model.rule_ids:
            return False
        return resource_matches(resource, model.scope)

    @staticmethod
    def _time_valid(model: Exemption, moment) -> bool:
        start = parse_iso(model.valid_from)
        end = parse_iso(model.valid_until)
        return start <= moment <= end

    def _validate_payload(
        self, payload: Any
    ) -> tuple[dict[str, Any], tuple[str, ...], Any, Any, str, str | None]:
        if not isinstance(payload, dict):
            raise PolicyDocumentError("豁免请求必须是 JSON 对象")
        scope = payload.get("scope", {})
        if scope is None:
            scope = {}
        if not isinstance(scope, dict):
            raise PolicyDocumentError("豁免 scope 必须是对象", {"actual_type": type(scope).__name__})
        unknown = set(scope) - _VALID_SCOPE_KEYS
        if unknown:
            raise PolicyDocumentError(
                f"豁免 scope 含未知键: {sorted(unknown)}", {"unknown": sorted(unknown)}
            )
        labels = scope.get("labels")
        if labels is not None and (
            not isinstance(labels, dict)
            or not all(isinstance(k, str) and isinstance(v, str) for k, v in labels.items())
        ):
            raise PolicyDocumentError("scope.labels 必须是 字符串->字符串 对象")

        rule_ids = payload.get("rule_ids", [])
        if not isinstance(rule_ids, list) or not all(isinstance(r, str) for r in rule_ids):
            raise PolicyDocumentError("rule_ids 必须是字符串数组")

        reason = payload.get("reason", "")
        if not isinstance(reason, str):
            raise PolicyDocumentError("reason 必须是字符串")

        idem_key = payload.get("idempotency_key")
        if idem_key is not None and not isinstance(idem_key, str):
            raise PolicyDocumentError("idempotency_key 必须是字符串")

        valid_from_raw = payload.get("valid_from")
        valid_until_raw = payload.get("valid_until")
        if not isinstance(valid_from_raw, str) or not isinstance(valid_until_raw, str):
            raise PolicyDocumentError("valid_from / valid_until 必须是 ISO8601 字符串")
        try:
            valid_from = parse_iso(valid_from_raw)
            valid_until = parse_iso(valid_until_raw)
        except ValueError as exc:
            raise PolicyDocumentError(f"豁免时间格式非法: {exc}") from exc
        if valid_from > valid_until:
            raise PolicyDocumentError(
                "豁免有效期非法：valid_from 晚于 valid_until",
                {"valid_from": valid_from_raw, "valid_until": valid_until_raw},
            )
        return scope, tuple(rule_ids), valid_from, valid_until, reason, idem_key

    @staticmethod
    def _to_model(record: dict[str, Any]) -> Exemption:
        return Exemption(
            exemption_id=record["exemption_id"],
            idempotency_key=record.get("idempotency_key"),
            scope=record.get("scope", {}),
            rule_ids=tuple(record.get("rule_ids", [])),
            valid_from=record["valid_from"],
            valid_until=record["valid_until"],
            reason=record.get("reason", ""),
            status=ExemptionStatus(record["status"]),
            requested_at=record["requested_at"],
            decided_at=record.get("decided_at"),
        )
