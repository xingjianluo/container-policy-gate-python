"""判定记录仓库：不可变、幂等、内容指纹。

- 每条判定永久保存（含资源快照、策略版本、策略指纹、全部命中依据）；
- idempotency_key 唯一：重复提交返回原记录，不产生重复副作用；
- 历史判定不被后续策略变化或重算覆盖。
"""

from __future__ import annotations

from typing import Any

from .errors import StorageError
from .models import Action, Decision, RuleHit, Severity, Verdict
from .storage import JsonStore

_DEFAULT_DATA: dict[str, Any] = {"decisions": {}, "idempotency": {}}


class DecisionStore:
    """判定记录仓库。"""

    def __init__(self, store: JsonStore) -> None:
        self._store = store

    def save_if_absent(
        self, decision: Decision, *, resource_snapshot: dict[str, Any]
    ) -> Decision:
        """幂等保存。

        - idempotency_key 已存在：返回既有判定，本次不写任何新记录；
        - decision_id 已存在（不同幂等键撞号，概率极低）：抛 StorageError。
        调用方必须在评估前先查幂等键；本方法在锁内做最终裁决，
        保证并发提交只有一条记录落盘。
        """
        payload = self._to_record(decision, resource_snapshot)
        with self._store.mutate() as data:
            decisions = data.setdefault("decisions", {})
            idempotency = data.setdefault("idempotency", {})

            if decision.idempotency_key is not None:
                existing_id = idempotency.get(self._ns(decision.idempotency_key))
                if existing_id is not None:
                    return self._to_model(decisions[existing_id], include_snapshot=False)

            if decision.decision_id in decisions:
                # 正常不可达：ID 随机且幂等键已先行去重
                raise StorageError(
                    f"判定 ID 冲突: {decision.decision_id}",
                    {"decision_id": decision.decision_id},
                )
            decisions[decision.decision_id] = payload
            if decision.idempotency_key is not None:
                idempotency[self._ns(decision.idempotency_key)] = decision.decision_id
            return decision

    def get(self, decision_id: str) -> Decision | None:
        """按 ID 读取；不存在返回 None。"""
        data = self._store.load()
        record = data.get("decisions", {}).get(decision_id)
        return self._to_model(record, include_snapshot=False) if record else None

    def get_record(self, decision_id: str) -> dict[str, Any] | None:
        """读取完整记录（含资源快照，供复现）。"""
        data = self._store.load()
        return data.get("decisions", {}).get(decision_id)

    def get_by_idempotency_key(self, key: str) -> Decision | None:
        data = self._store.load()
        decision_id = data.get("idempotency", {}).get(self._ns(key))
        if decision_id is None:
            return None
        return self._to_model(data["decisions"][decision_id], include_snapshot=False)

    def list_all(self) -> list[Decision]:
        data = self._store.load()
        return [
            self._to_model(record, include_snapshot=False)
            for record in data.get("decisions", {}).values()
        ]

    @staticmethod
    def _ns(key: str) -> str:
        return f"admit:{key}"

    @staticmethod
    def _to_record(decision: Decision, resource_snapshot: dict[str, Any]) -> dict[str, Any]:
        return {
            "decision_id": decision.decision_id,
            "idempotency_key": decision.idempotency_key,
            "resource_ref": decision.resource_ref,
            "resource": resource_snapshot,
            "resource_fingerprint": decision.resource_fingerprint,
            "policy_name": decision.policy_name,
            "policy_version": decision.policy_version,
            "policy_fingerprint": decision.policy_fingerprint,
            "action": decision.action.value,
            "rationale": decision.rationale,
            "decided_at": decision.decided_at,
            "hits": [
                {
                    "rule_id": h.rule_id,
                    "verdict": h.verdict.value,
                    "severity": h.severity.value,
                    "field": h.field,
                    "operator": h.operator,
                    "expected": h.expected,
                    "actual": h.actual,
                    "reason": h.reason,
                    "exempted": h.exempted,
                    "exemption_id": h.exemption_id,
                }
                for h in decision.hits
            ],
        }

    @staticmethod
    def _to_model(record: dict[str, Any], *, include_snapshot: bool) -> Decision:
        hits = tuple(
            RuleHit(
                rule_id=h["rule_id"],
                verdict=Verdict(h["verdict"]),
                severity=Severity(h["severity"]),
                field=h["field"],
                operator=h["operator"],
                expected=h.get("expected"),
                actual=h.get("actual"),
                reason=h["reason"],
                exempted=h.get("exempted", False),
                exemption_id=h.get("exemption_id"),
            )
            for h in record["hits"]
        )
        return Decision(
            decision_id=record["decision_id"],
            idempotency_key=record.get("idempotency_key"),
            resource_ref=record["resource_ref"],
            resource_fingerprint=record["resource_fingerprint"],
            policy_name=record["policy_name"],
            policy_version=record["policy_version"],
            policy_fingerprint=record["policy_fingerprint"],
            action=Action(record["action"]),
            hits=hits,
            rationale=record["rationale"],
            decided_at=record["decided_at"],
        )
