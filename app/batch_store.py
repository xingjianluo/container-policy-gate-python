"""批量判定记录仓库：不可变、按批次内容指纹去重。

- 批次记录以 batch_fingerprint 唯一标识：同一批资源（与提交顺序无关）在
  同一策略版本下重复提交时返回首次记录，不产生重复副作用；
- 批次记录内联条目结论（含条目级判定），条目判定本身另由 DecisionStore
  按内容指纹去重，两层去重互不依赖；
- 批次记录一旦落盘不再修改，重复提交只读回首次结论。
"""

from __future__ import annotations

from typing import Any

from .decision_store import decision_from_record, decision_to_record
from .models import (
    Action,
    BatchItemResult,
    BatchResult,
    BatchSummary,
)
from .storage import JsonStore

_DEFAULT_DATA: dict[str, Any] = {"batches": {}, "fingerprints": {}}


class BatchStore:
    """批量判定记录仓库。"""

    def __init__(self, store: JsonStore) -> None:
        self._store = store

    def save_if_absent(self, batch: BatchResult) -> tuple[BatchResult, bool]:
        """幂等保存：指纹已存在返回 (既有记录, True)，否则落盘返回 (本次记录, False)。

        锁内完成 check-then-write，并发提交同一批次只有一条记录落盘。
        """
        payload = self._to_record(batch)
        with self._store.mutate() as data:
            batches = data.setdefault("batches", {})
            fingerprints = data.setdefault("fingerprints", {})

            existing_id = fingerprints.get(batch.batch_fingerprint)
            if existing_id is not None:
                return self._to_model(batches[existing_id]), True

            batches[batch.batch_id] = payload
            fingerprints[batch.batch_fingerprint] = batch.batch_id
            return batch, False

    def get_by_fingerprint(self, batch_fingerprint: str) -> BatchResult | None:
        """按批次内容指纹读取；不存在返回 None。"""
        data = self._store.load()
        batch_id = data.get("fingerprints", {}).get(batch_fingerprint)
        if batch_id is None:
            return None
        return self._to_model(data["batches"][batch_id])

    def get(self, batch_id: str) -> BatchResult | None:
        """按批次 ID 读取；不存在返回 None。"""
        data = self._store.load()
        record = data.get("batches", {}).get(batch_id)
        return self._to_model(record) if record else None

    def list_all(self) -> list[BatchResult]:
        data = self._store.load()
        return [self._to_model(r) for r in data.get("batches", {}).values()]

    # ---- serialization ----

    @staticmethod
    def _to_record(batch: BatchResult) -> dict[str, Any]:
        summary = batch.summary
        return {
            "batch_id": batch.batch_id,
            "batch_fingerprint": batch.batch_fingerprint,
            "policy_name": batch.policy_name,
            "policy_version": batch.policy_version,
            "policy_fingerprint": batch.policy_fingerprint,
            "created_at": batch.created_at,
            "summary": {
                "total": summary.total,
                "decided": summary.decided,
                "invalid": summary.invalid,
                "allow": summary.allow,
                "allow_with_warning": summary.allow_with_warning,
                "deny": summary.deny,
                "action": summary.action.value,
                "rationale": summary.rationale,
            },
            "items": [
                {
                    "index": item.index,
                    "status": item.status,
                    "resource_ref": item.resource_ref,
                    "reused": item.reused,
                    "item_fingerprint": item.item_fingerprint,
                    "decision": (
                        decision_to_record(item.decision)
                        if item.decision is not None
                        else None
                    ),
                    "error": item.error,
                }
                for item in batch.items
            ],
        }

    @staticmethod
    def _to_model(record: dict[str, Any]) -> BatchResult:
        s = record["summary"]
        summary = BatchSummary(
            total=s["total"],
            decided=s["decided"],
            invalid=s["invalid"],
            allow=s["allow"],
            allow_with_warning=s["allow_with_warning"],
            deny=s["deny"],
            action=Action(s["action"]),
            rationale=s["rationale"],
        )
        items = tuple(
            BatchItemResult(
                index=i["index"],
                status=i["status"],
                resource_ref=i.get("resource_ref"),
                decision=(
                    decision_from_record(i["decision"])
                    if i.get("decision") is not None
                    else None
                ),
                reused=i.get("reused", False),
                error=i.get("error"),
                # 历史记录无条目指纹时，已判定条目用资源内容指纹回填，
                # 使换序重交的重排对旧记录同样生效
                item_fingerprint=i.get("item_fingerprint")
                or (i["decision"]["resource_fingerprint"] if i.get("decision") else ""),
            )
            for i in record["items"]
        )
        return BatchResult(
            batch_id=record["batch_id"],
            batch_fingerprint=record["batch_fingerprint"],
            policy_name=record["policy_name"],
            policy_version=record["policy_version"],
            policy_fingerprint=record["policy_fingerprint"],
            summary=summary,
            items=items,
            created_at=record["created_at"],
            reused=False,
        )
