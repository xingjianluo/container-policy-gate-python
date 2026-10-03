"""批量准入服务。

语义要点：
- 整批共用同一个策略快照（进入批次时选定一次版本+指纹），
  批次执行期间发布新版本不影响本批；
- 单条资源不合法只标记该条（status=invalid），不拖垮整批，也不静默放行；
- 条目级按 (策略版本指纹 + 资源内容指纹) 去重：无幂等标识的重复上报
  自动复用既有判定，不产生重复记录；内容或策略版本变化则视为新判定；
- 批次级按排序后的条目指纹去重：同一批资源换序提交，批次标识与汇总一致；
- 换序/重复提交复用首次批次结论时，逐条结果按本次提交顺序重排后返回，
  位置与本次请求里的资源一一对应（不合法条目也落在它原本的位置上）。
"""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Any

from .batch_store import BatchStore
from .clock import Clock, to_iso
from .errors import PolicyDocumentError, ResourceValidationError
from .evaluator import Evaluator
from .models import (
    BATCH_ITEM_DECIDED,
    BATCH_ITEM_INVALID,
    Action,
    BatchItemResult,
    BatchResult,
    BatchSummary,
    Policy,
)
from .resource import fingerprint, resource_ref, validate_resource

logger = logging.getLogger("policy_gate.batch")


class BatchService:
    """批量准入：一次请求判定一组资源清单。"""

    def __init__(
        self,
        batch_store: BatchStore,
        evaluator: Evaluator,
        clock: Clock,
    ) -> None:
        self._batches = batch_store
        self._evaluator = evaluator
        self._clock = clock

    def admit_batch(
        self,
        resources: list[Any],
        policy_name: str,
        *,
        policy_version: int | None = None,
    ) -> BatchResult:
        """对一组资源清单执行批量准入判定。

        - resources 必须是非空数组；数组内个别元素不合法只标记该条；
        - 整批落在进入批次时选定的同一策略快照上；
        - 同一批内容（与顺序无关）在同一策略版本下重复提交，
          返回首次批次的结论并标记 reused。
        """
        if not isinstance(resources, list) or not resources:
            raise PolicyDocumentError(
                "批量准入需要非空的资源清单数组 'resources'",
                {"actual_type": type(resources).__name__},
            )

        # 1. 进入批次时选定一次策略快照：本批所有条目共用同一版本+指纹
        policy = self._evaluator.select_policy(policy_name, policy_version)

        # 2. 批次内容指纹：条目指纹排序后计算，与提交顺序无关
        item_fingerprints = sorted(fingerprint(item) for item in resources)
        batch_fp = fingerprint(
            {
                "policy_name": policy.name,
                "policy_version": policy.version,
                "policy_fingerprint": policy.fingerprint,
                "items": item_fingerprints,
            }
        )

        # 3. 批次级幂等短路：同内容批次重复提交直接复用首次结论，
        #    但逐条结果必须按本次提交顺序重排后再返回
        existing = self._batches.get_by_fingerprint(batch_fp)
        if existing is not None:
            logger.info(
                "batch dedup-hit batch_id=%s policy=%s@v%s fp=%s",
                existing.batch_id,
                existing.policy_name,
                existing.policy_version,
                existing.policy_fingerprint[:12],
            )
            return replace(self._reorder_to_request(existing, resources), reused=True)

        logger.info(
            "batch start items=%d policy=%s@v%s fp=%s batch_fp=%s",
            len(resources),
            policy.name,
            policy.version,
            policy.fingerprint[:12],
            batch_fp[:12],
        )

        # 4. 逐条判定（同一策略快照；不合法条目单独标记，不中断整批）
        items = tuple(
            self._admit_item(index, resource, policy)
            for index, resource in enumerate(resources)
        )

        # 5. 汇总（只依赖计数，与条目顺序无关）
        summary = self._summarize(items)
        batch = BatchResult(
            batch_id=f"batch-{batch_fp[:24]}",
            batch_fingerprint=batch_fp,
            policy_name=policy.name,
            policy_version=policy.version,
            policy_fingerprint=policy.fingerprint,
            summary=summary,
            items=items,
            created_at=to_iso(self._clock.now()),
        )

        # 6. 批次落盘（锁内最终裁决：并发同批提交只有一份记录）
        saved, reused = self._batches.save_if_absent(batch)
        logger.info(
            "batch done batch_id=%s action=%s decided=%d invalid=%d reused=%s rationale=%s",
            saved.batch_id,
            saved.summary.action.value,
            saved.summary.decided,
            saved.summary.invalid,
            reused,
            saved.summary.rationale,
        )
        if reused:
            # 并发竞争中落败：拿到的是先落盘那一份（条目顺序可能不同），
            # 同样按本次提交顺序重排后再返回
            return replace(self._reorder_to_request(saved, resources), reused=True)
        return saved

    def get_batch(self, batch_id: str) -> BatchResult | None:
        return self._batches.get(batch_id)

    # ---- internal ----

    def _reorder_to_request(
        self, stored: BatchResult, resources: list[Any]
    ) -> BatchResult:
        """把已存批次的条目按本次提交顺序重排，保证位置一一对应。

        按条目内容指纹做多重集匹配：内容完全相同的条目结论也相同，
        按出现先后依次配对即可；index 重新编号为本次提交的位置。
        批次标识与整批汇总保持不变（与顺序无关）。
        无法完整对应时（如历史记录缺条目指纹）保持原顺序并告警，绝不错位。
        """
        pools: dict[str, list[BatchItemResult]] = {}
        for item in stored.items:
            pools.setdefault(item.item_fingerprint, []).append(item)

        reordered: list[BatchItemResult] = []
        for position, raw in enumerate(resources):
            pool = pools.get(fingerprint(raw))
            if not pool:
                logger.warning(
                    "batch reorder fallback batch_id=%s：条目指纹无法与本次提交"
                    "一一对应，保持已存顺序返回",
                    stored.batch_id,
                )
                return stored
            reordered.append(replace(pool.pop(0), index=position))

        logger.info(
            "batch reorder batch_id=%s items=%d：逐条结果已按本次提交顺序重排",
            stored.batch_id,
            len(reordered),
        )
        return replace(stored, items=tuple(reordered))

    def _admit_item(self, index: int, resource: Any, policy: Policy) -> BatchItemResult:
        """判定单条资源；不合法时返回 invalid 条目而不是中断整批。"""
        item_fp = fingerprint(resource)
        try:
            validate_resource(resource)
        except ResourceValidationError as exc:
            ref = resource_ref(resource) if isinstance(resource, dict) else None
            logger.warning(
                "batch item %d invalid ref=%s code=%s reason=%s",
                index,
                ref,
                exc.code,
                exc.message,
            )
            return BatchItemResult(
                index=index,
                status=BATCH_ITEM_INVALID,
                resource_ref=ref,
                decision=None,
                reused=False,
                error=exc.to_dict(),
                item_fingerprint=item_fp,
            )

        decision, reused = self._evaluator.admit_against_policy(resource, policy)
        logger.info(
            "batch item %d ref=%s action=%s reused=%s decision_id=%s 依据=%s",
            index,
            decision.resource_ref,
            decision.action.value,
            reused,
            decision.decision_id,
            decision.rationale,
        )
        return BatchItemResult(
            index=index,
            status=BATCH_ITEM_DECIDED,
            resource_ref=decision.resource_ref,
            decision=decision,
            reused=reused,
            error=None,
            item_fingerprint=item_fp,
        )

    @staticmethod
    def _summarize(items: tuple[BatchItemResult, ...]) -> BatchSummary:
        decided = [i for i in items if i.status == BATCH_ITEM_DECIDED]
        invalid = len(items) - len(decided)
        allow = sum(1 for i in decided if i.decision.action is Action.ALLOW)
        warn = sum(1 for i in decided if i.decision.action is Action.ALLOW_WITH_WARNING)
        deny = sum(1 for i in decided if i.decision.action is Action.DENY)

        # 整体处置：任一拒绝则整批拒绝；存在不合法条目时至少按告警对待，
        # 保证“不合法”在汇总层面可见，绝不静默放行
        if deny:
            action = Action.DENY
        elif warn or invalid:
            action = Action.ALLOW_WITH_WARNING
        else:
            action = Action.ALLOW

        rationale = (
            f"批量判定：共 {len(items)} 条，"
            f"{deny} 条拒绝、{warn} 条告警放行、{allow} 条放行、"
            f"{invalid} 条资源不合法（已单独标记，未参与判定）"
        )
        return BatchSummary(
            total=len(items),
            decided=len(decided),
            invalid=invalid,
            allow=allow,
            allow_with_warning=warn,
            deny=deny,
            action=action,
            rationale=rationale,
        )
