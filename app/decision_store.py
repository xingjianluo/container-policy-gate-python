"""判定记录仓库：不可变、幂等、内容指纹。

- 每条判定永久保存（含资源快照、策略版本、策略指纹、全部命中依据）；
- idempotency_key 唯一：重复提交返回原记录，不产生重复副作用；
- 内容指纹去重：无幂等标识时，同一资源内容在同一策略版本（指纹）下
  重复提交复用既有判定；内容或策略版本变化则视为新判定；
- 历史判定不被后续策略变化或重算覆盖。
"""

from __future__ import annotations

from typing import Any

from .errors import StorageError
from .models import Action, Decision, RuleHit, Severity, Verdict
from .storage import JsonStore

_DEFAULT_DATA: dict[str, Any] = {"decisions": {}, "idempotency": {}, "content": {}}


def content_dedup_key(
    policy_name: str,
    policy_version: int,
    policy_fingerprint: str,
    resource_fingerprint: str,
) -> str:
    """内容去重键：同一份资源内容 + 同一策略版本（指纹）=> 同一次判定。

    指纹均为定长十六进制，直接拼接无歧义。
    """
    return (
        f"content:{policy_name}:{policy_version}:"
        f"{policy_fingerprint}:{resource_fingerprint}"
    )


def decision_to_record(decision: Decision) -> dict[str, Any]:
    """序列化判定（不含资源快照；快照仅由判定仓库自己持久化）。"""
    return {
        "decision_id": decision.decision_id,
        "idempotency_key": decision.idempotency_key,
        "resource_ref": decision.resource_ref,
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


def decision_from_record(record: dict[str, Any]) -> Decision:
    """从记录字典还原判定模型。"""
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


class DecisionStore:
    """判定记录仓库。"""

    def __init__(self, store: JsonStore) -> None:
        self._store = store

    def save_if_absent(
        self,
        decision: Decision,
        *,
        resource_snapshot: dict[str, Any],
        content_key: str | None = None,
    ) -> tuple[Decision, bool]:
        """幂等保存，返回 (最终判定, 是否复用既有记录)。

        - idempotency_key 已存在：返回既有判定，本次不写任何新记录；
        - content_key 已存在（同内容同策略版本）：返回既有判定；
        - decision_id 已存在（不同幂等键撞号，概率极低）：抛 StorageError。
        调用方必须在评估前先查幂等键/内容键；本方法在锁内做最终裁决，
        保证并发提交只有一条记录落盘。
        """
        payload = self._to_record(decision, resource_snapshot)
        with self._store.mutate() as data:
            decisions = data.setdefault("decisions", {})
            idempotency = data.setdefault("idempotency", {})
            content = data.setdefault("content", {})

            if decision.idempotency_key is not None:
                existing_id = idempotency.get(self._ns(decision.idempotency_key))
                if existing_id is not None:
                    return self._to_model(decisions[existing_id], include_snapshot=False), True
            elif content_key is not None:
                # 内容去重仅作用于无幂等键的提交：显式不同的幂等键
                # 视为调用方有意区分的多次判定，各自落盘
                existing_id = content.get(content_key)
                if existing_id is not None:
                    return self._to_model(decisions[existing_id], include_snapshot=False), True

            if decision.decision_id in decisions:
                # 正常不可达：ID 随机且幂等键已先行去重
                raise StorageError(
                    f"判定 ID 冲突: {decision.decision_id}",
                    {"decision_id": decision.decision_id},
                )
            decisions[decision.decision_id] = payload
            if decision.idempotency_key is not None:
                idempotency[self._ns(decision.idempotency_key)] = decision.decision_id
            if content_key is not None:
                # 同内容已登记过时保留首次映射（首决确定性）
                content.setdefault(content_key, decision.decision_id)
            return decision, False

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

    def get_by_content_key(self, content_key: str) -> Decision | None:
        """按内容去重键读取；不存在返回 None。"""
        data = self._store.load()
        decision_id = data.get("content", {}).get(content_key)
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
        record = decision_to_record(decision)
        record["resource"] = resource_snapshot
        return record

    @staticmethod
    def _to_model(record: dict[str, Any], *, include_snapshot: bool) -> Decision:
        return decision_from_record(record)
