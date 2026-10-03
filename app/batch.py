"""批量准入服务。

语义要点：
- 整批共用同一个策略快照（进入批次时选定一次版本+指纹），
  批次执行期间发布新版本不影响本批；
- 单条资源不合法只标记该条（status=invalid），不拖垮整批，也不静默放行；
- 条目级按 (策略版本指纹 + 资源内容指纹) 去重：无幂等标识的重复上报
  自动复用既有判定，不产生重复记录；内容或策略版本变化则视为新判定；
- 批次级按排序后的条目指纹去重：同一批资源换序提交，批次标识与汇总一致；
- 换序/重复提交命中既有批次时，逐条结果按【本次请求】的资源顺序重排返回，
  与提交位置一一对应（不合法条目也落在它本次的位置上）。
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from dataclasses import replace
from typing import Any

from .batch_store import BatchStore
from .clock import Clock, to_iso
from .errors import PolicyDocumentError, ResourceValidationError, StorageError
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
          复用首次批次的标识与汇总并标记 reused，但逐条结果按
          【本次请求】的提交顺序排列，与资源位置一一对应。
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
        #    但逐条结果必须按【本次请求】的资源顺序重排后再返回
        existing = self._batches.get_by_fingerprint(batch_fp)
        if existing is not None:
            logger.info(
                "batch dedup-hit batch_id=%s policy=%s@v%s fp=%s",
                existing.batch_id,
                existing.policy_name,
                existing.policy_version,
                existing.policy_fingerprint[:12],
            )
            return self._replay_in_request_order(existing, resources)

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

        # 6. 批次落盘（锁内最终裁决：并发同批提交只有一份记录）。
        #    若被并发请求抢先落盘，批次标识/汇总以落盘记录为准，
        #    但逐条结果用本次请求自己算出的条目（顺序即本次提交顺序）。
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
        return replace(saved, items=items, reused=True) if reused else saved

    def get_batch(self, batch_id: str) -> BatchResult | None:
        return self._batches.get(batch_id)

    # ---- internal ----

    def _replay_in_request_order(
        self, stored: BatchResult, resources: list[Any]
    ) -> BatchResult:
        """把既有批次的条目结论按本次请求的资源顺序重排后返回。

        对齐键是条目内容指纹（多重集匹配：批内完全相同的条目按出现
        次序依次配对，内容相同结论也相同，配对结果不影响正确性）；
        重排后 index 改写为本次请求中的位置，不合法条目同样落回
        它本次的位置。命中即复用：decided 条目标记 reused=True，
        整个过程不产生任何新的判定/批次记录。
        """
        pools: dict[str, deque[BatchItemResult]] = defaultdict(deque)
        for item in stored.items:
            # 旧记录缺 item_fingerprint 时，decided 条目回退用判定的资源指纹
            fp = item.item_fingerprint or (
                item.decision.resource_fingerprint if item.decision is not None else ""
            )
            pools[fp].append(item)

        reordered: list[BatchItemResult] = []
        for new_index, resource in enumerate(resources):
            fp = fingerprint(resource)
            pool = pools.get(fp)
            if not pool:
                # 批次指纹一致 => 条目指纹多重集必然一致；走到这里说明
                # 存储记录损坏，必须明确报错，绝不能静默错位
                raise StorageError(
                    "批次记录与本次请求的条目无法对齐（记录可能损坏）",
                    {
                        "batch_id": stored.batch_id,
                        "request_index": new_index,
                        "item_fingerprint": fp,
                    },
                )
            item = pool.popleft()
            reordered.append(
                replace(
                    item,
                    index=new_index,
                    reused=item.reused or item.status == BATCH_ITEM_DECIDED,
                )
            )

        logger.info(
            "batch replay reordered batch_id=%s items=%d 按本次提交顺序对齐",
            stored.batch_id,
            len(reordered),
        )
        return replace(stored, items=tuple(reordered), reused=True)

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
