"""策略评估引擎。

判定流程：
1. 幂等短路：idempotency_key 命中既有判定时直接返回，不产生重复记录；
   调用方不带幂等标识时，自动派生内容键
   content:{policy_name}:{policy_version}:{policy_fingerprint}:{resource_fingerprint}，
   同一份资源内容在同一策略版本下重复提交（串行重试或并发）都会收口到同一条判定；
   资源内容变更或策略版本变化会派生出不同的键，必然触发一次新判定；
2. 校验资源（必填字段缺失 -> ResourceValidationError，绝不静默放行）；
3. 选定策略版本（显式版本或最新版）；批量场景在批次开始时选定一次，
   整批落在同一策略快照上，不受批次执行期间新版本发布影响；
4. 逐条规则：选择器匹配 -> 字段读取 -> 算子判定 -> 记录命中与依据；
5. 叠加有效豁免（仅 approved、范围匹配、在有效期内）；
   严重级别(severity)与处置(action)分离：
   - deny 类违规且未豁免  -> DENY
   - 违规但被豁免          -> ALLOW_WITH_WARNING
   - warn 类规则           -> ALLOW_WITH_WARNING（无需豁免）
   - 其余                  -> ALLOW；
6. 结论不可变落盘：资源快照 + 策略版本 + 策略指纹 + 全部依据；
   批量场景额外落一条批次记录（批次内容指纹为主键），整批重复提交原样复用；
7. replay 按记录的版本与指纹取回历史策略重算并逐字段比对，证明可复现。
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from .clock import Clock, parse_iso, to_iso
from .decision_store import DecisionStore
from .errors import (
    PolicyDocumentError,
    PolicyVersionConflict,
    ResourceValidationError,
    StorageError,
)
from .exemption import ExemptionService
from .models import (
    Action,
    BatchItemResult,
    BatchResult,
    Decision,
    Policy,
    Rule,
    RuleHit,
    Severity,
    Verdict,
)
from .operators import evaluate
from .policy_store import PolicyStore
from .resource import (
    fingerprint,
    get_field_value,
    is_missing,
    resource_fingerprint,
    resource_matches,
    resource_ref,
    snapshot,
    validate_resource,
)

logger = logging.getLogger("policy_gate.evaluator")

# 违规严重级别排序，用于 rationale 中的最高级别描述
_SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class Evaluator:
    """准入判定引擎。"""

    def __init__(
        self,
        policy_store: PolicyStore,
        decision_store: DecisionStore,
        exemption_service: ExemptionService,
        clock: Clock,
    ) -> None:
        self._policies = policy_store
        self._decisions = decision_store
        self._exemptions = exemption_service
        self._clock = clock

    def admit(
        self,
        resource: dict[str, Any],
        policy_name: str,
        *,
        policy_version: int | None = None,
        idempotency_key: str | None = None,
    ) -> Decision:
        """执行准入判定（按显式幂等键或内容指纹幂等）。"""
        # 1. 幂等短路（重复提交直接返回既有结论）
        if idempotency_key is not None:
            existing = self._decisions.get_by_idempotency_key(idempotency_key)
            if existing is not None:
                logger.info(
                    "admit idempotent-hit key=%s decision_id=%s",
                    idempotency_key,
                    existing.decision_id,
                )
                return existing

        # 2. 资源校验：必填字段缺失等问题在此被明确拒绝
        validate_resource(resource)

        # 3. 选定策略版本
        policy = self._select_policy(policy_name, policy_version)

        # 3b. 无显式幂等标识时派生内容键：同内容 + 同策略版本 => 同键
        if idempotency_key is None:
            idempotency_key = self._content_key(policy, resource)
            existing = self._decisions.get_by_idempotency_key(idempotency_key)
            if existing is not None:
                logger.info(
                    "admit content-dedup-hit key=%s decision_id=%s",
                    idempotency_key,
                    existing.decision_id,
                )
                return existing

        # 4/5. 评估 + 豁免
        decision = self._evaluate(resource, policy, idempotency_key)

        # 6. 不可变落盘（锁内最终幂等裁决，保证并发下唯一记录）
        saved = self._decisions.save_if_absent(
            decision, resource_snapshot=snapshot(resource)
        )
        logger.info(
            "admit decision_id=%s resource=%s policy=%s@v%s fp=%s action=%s rationale=%s",
            saved.decision_id,
            saved.resource_ref,
            saved.policy_name,
            saved.policy_version,
            saved.policy_fingerprint[:12],
            saved.action.value,
            saved.rationale,
        )
        for hit in saved.hits:
            logger.debug(
                "hit rule=%s verdict=%s severity=%s exempted=%s reason=%s",
                hit.rule_id,
                hit.verdict.value,
                hit.severity.value,
                hit.exempted,
                hit.reason,
            )
        return saved

    def find_existing(
        self,
        resource: dict[str, Any],
        policy_name: str,
        *,
        policy_version: int | None = None,
        idempotency_key: str | None = None,
    ) -> Decision | None:
        """无副作用地查找本次提交会复用的既有判定（供上层标注 idempotent_hit）。"""
        if idempotency_key is not None:
            return self._decisions.get_by_idempotency_key(idempotency_key)
        validate_resource(resource)
        policy = self._select_policy(policy_name, policy_version)
        return self._decisions.get_by_idempotency_key(
            self._content_key(policy, resource)
        )

    @staticmethod
    def _content_key(policy: Policy, resource: dict[str, Any]) -> str:
        """内容幂等键：同一份资源内容 + 同一策略版本（含内容指纹）=> 同一个键。"""
        return (
            f"content:{policy.name}:{policy.version}:"
            f"{policy.fingerprint}:{resource_fingerprint(resource)}"
        )

    # ---- 批量准入 ----

    def admit_batch(
        self,
        resources: list[Any],
        policy_name: str,
        *,
        policy_version: int | None = None,
    ) -> BatchResult:
        """批量准入：一组资源落在同一策略快照上逐条判定，并给出整批汇总。

        - 策略在批次开始时选定一次，批次执行期间发布新版本不影响本批；
        - 单条资源不合法只标记该条（error 可见），其余照常出结论；
        - 每条合法资源按内容键幂等：批内/跨批/并发的重复内容不产生重复记录；
        - 整批按 批次内容指纹（策略指纹 + 排序后的资源指纹列表）幂等：
          重复提交（含换序）复用首次批次的 batch_id 与汇总。
        """
        if not isinstance(resources, list) or not resources:
            raise PolicyDocumentError("批量准入需要非空的 resources 数组")

        # 批次级策略快照：只选定一次，整批共用
        policy = self._select_policy(policy_name, policy_version)
        item_fps = [fingerprint(r) for r in resources]
        batch_fp = fingerprint(
            {
                "policy": [policy.name, policy.version, policy.fingerprint],
                "items": sorted(item_fps),
            }
        )

        # 整批幂等短路：同批次内容重复提交直接复用首次结论
        existing = self._decisions.get_batch(batch_fp)
        if existing is not None:
            result = self._rebuild_batch(existing, resources, item_fps, policy)
            logger.info(
                "admit_batch idempotent-hit batch_id=%s policy=%s@v%s fp=%s summary=%s",
                result.batch_id,
                result.policy_name,
                result.policy_version,
                result.policy_fingerprint[:12],
                result.summary,
            )
            return result

        items = tuple(
            self._admit_one_for_batch(index, res, policy, item_fps[index])
            for index, res in enumerate(resources)
        )
        record = {
            "batch_id": uuid.uuid4().hex,
            "batch_fingerprint": batch_fp,
            "policy_name": policy.name,
            "policy_version": policy.version,
            "policy_fingerprint": policy.fingerprint,
            "decided_at": to_iso(self._clock.now()),
            "summary": self._summarize(items),
            "items": [
                (
                    {
                        "resource_fingerprint": item.resource_fingerprint,
                        "kind": "decision",
                        "decision_id": item.decision.decision_id,
                    }
                    if item.decision is not None
                    else {
                        "resource_fingerprint": item.resource_fingerprint,
                        "kind": "error",
                        "error": item.error,
                    }
                )
                for item in items
            ],
        }
        # 锁内最终裁决：并发提交同一批次只有一份批次记录
        saved, created = self._decisions.save_batch_if_absent(record)
        if not created:
            return self._rebuild_batch(saved, resources, item_fps, policy)

        result = BatchResult(
            batch_id=saved["batch_id"],
            batch_fingerprint=batch_fp,
            idempotent_hit=False,
            policy_name=policy.name,
            policy_version=policy.version,
            policy_fingerprint=policy.fingerprint,
            items=items,
            summary=saved["summary"],
            decided_at=saved["decided_at"],
        )
        logger.info(
            "admit_batch batch_id=%s policy=%s@v%s fp=%s summary=%s",
            result.batch_id,
            result.policy_name,
            result.policy_version,
            result.policy_fingerprint[:12],
            result.summary,
        )
        for item in result.items:
            if item.decision is not None:
                logger.info(
                    "batch-item[%d] resource=%s action=%s reused=%s rationale=%s",
                    item.index,
                    item.decision.resource_ref,
                    item.decision.action.value,
                    item.reused,
                    item.decision.rationale,
                )
            else:
                logger.info(
                    "batch-item[%d] invalid error=%s",
                    item.index,
                    (item.error or {}).get("message"),
                )
        return result

    def _admit_one_for_batch(
        self, index: int, resource: Any, policy: Policy, item_fp: str
    ) -> BatchItemResult:
        """判定批次中的单条资源；不合法的资源只标记自身，绝不影响整批。"""
        try:
            validate_resource(resource)
        except ResourceValidationError as exc:
            logger.info(
                "batch-item[%d] 资源不合法，单独标记: %s", index, exc.message
            )
            return BatchItemResult(
                index=index,
                status="invalid",
                resource_fingerprint=item_fp,
                error=exc.to_dict(),
            )

        key = self._content_key(policy, resource)
        existing = self._decisions.get_by_idempotency_key(key)
        if existing is not None:
            return BatchItemResult(
                index=index,
                status="decided",
                resource_fingerprint=item_fp,
                resource_ref=existing.resource_ref,
                decision=existing,
                reused=True,
            )

        decision = self._evaluate(resource, policy, key)
        saved = self._decisions.save_if_absent(
            decision, resource_snapshot=snapshot(resource)
        )
        # save_if_absent 返回既有记录说明并发下已被其他提交落盘 -> 本次为复用
        return BatchItemResult(
            index=index,
            status="decided",
            resource_fingerprint=item_fp,
            resource_ref=saved.resource_ref,
            decision=saved,
            reused=saved.decision_id != decision.decision_id,
        )

    def _rebuild_batch(
        self,
        record: dict[str, Any],
        resources: list[Any],
        item_fps: list[str],
        policy: Policy,
    ) -> BatchResult:
        """从批次记录重建结果：按当前请求顺序逐条对回存储的判定/错误。"""
        by_fp: dict[str, list[dict[str, Any]]] = {}
        for entry in record["items"]:
            by_fp.setdefault(entry["resource_fingerprint"], []).append(entry)

        items: list[BatchItemResult] = []
        for index, res in enumerate(resources):
            entry = by_fp[item_fps[index]].pop(0)
            if entry["kind"] == "decision":
                decision = self._decisions.get(entry["decision_id"])
                assert decision is not None  # 判定记录不可变且永久保存
                items.append(
                    BatchItemResult(
                        index=index,
                        status="decided",
                        resource_fingerprint=item_fps[index],
                        resource_ref=decision.resource_ref,
                        decision=decision,
                        reused=True,
                    )
                )
            else:
                items.append(
                    BatchItemResult(
                        index=index,
                        status="invalid",
                        resource_fingerprint=item_fps[index],
                        error=entry["error"],
                    )
                )
        result_items = tuple(items)
        return BatchResult(
            batch_id=record["batch_id"],
            batch_fingerprint=record["batch_fingerprint"],
            idempotent_hit=True,
            policy_name=record["policy_name"],
            policy_version=record["policy_version"],
            policy_fingerprint=record["policy_fingerprint"],
            items=result_items,
            summary=record["summary"],  # 汇总以首次落盘为准，重复提交完全一致
            decided_at=record["decided_at"],
        )

    @staticmethod
    def _summarize(items: tuple[BatchItemResult, ...]) -> dict[str, Any]:
        """整批汇总：各处置计数 + 汇总结论（顺序无关，换序提交结果一致）。"""
        counts = {
            Action.ALLOW: 0,
            Action.ALLOW_WITH_WARNING: 0,
            Action.DENY: 0,
        }
        invalid = 0
        reused = 0
        for item in items:
            if item.decision is not None:
                counts[item.decision.action] += 1
                if item.reused:
                    reused += 1
            else:
                invalid += 1
        if counts[Action.DENY] or invalid:
            overall = Action.DENY.value
        elif counts[Action.ALLOW_WITH_WARNING]:
            overall = Action.ALLOW_WITH_WARNING.value
        else:
            overall = Action.ALLOW.value
        rationale = (
            f"整批 {len(items)} 条：放行 {counts[Action.ALLOW]}，"
            f"告警放行 {counts[Action.ALLOW_WITH_WARNING]}，"
            f"拒绝 {counts[Action.DENY]}，资源不合法 {invalid}"
            f"（复用既有判定 {reused} 条）"
        )
        return {
            "total": len(items),
            "allow": counts[Action.ALLOW],
            "allow_with_warning": counts[Action.ALLOW_WITH_WARNING],
            "deny": counts[Action.DENY],
            "invalid": invalid,
            "reused": reused,
            "overall_action": overall,
            "rationale": rationale,
        }

    def get_decision(self, decision_id: str) -> Decision | None:
        return self._decisions.get(decision_id)

    def replay(self, decision_id: str) -> dict[str, Any]:
        """按记录中的策略版本+指纹重算，逐字段比对历史结论。

        - 策略版本缺失或指纹不符 -> 拒绝复现（错误明确）；
        - 重算时冻结在历史判定时刻，豁免采纳情况以记录的命中依据为准；
        - 重算结果与记录不一致 -> 抛错，说明可复现性被破坏；
        - 一致则返回记录、重算结果与比对明细。
        """
        record = self._decisions.get_record(decision_id)
        if record is None:
            raise PolicyDocumentError(f"判定记录不存在: {decision_id}")

        policy = self._policies.get_for_replay(
            record["policy_name"],
            record["policy_version"],
            record["policy_fingerprint"],
        )
        stored = self._decisions.get(decision_id)
        assert stored is not None

        # 用历史记录中的命中依据构造“豁免快照”：某条规则当时是否被哪条豁免采纳。
        exemption_snapshot = {
            h["rule_id"]: h.get("exemption_id")
            for h in record["hits"]
            if h.get("exempted") and h.get("exemption_id")
        }
        frozen_moment = parse_iso(stored.decided_at)

        resource_snap = record["resource"]
        recomputed = self._evaluate(
            resource_snap,
            policy,
            idempotency_key=None,
            decision_id=stored.decision_id,
            decided_at=stored.decided_at,
            moment=frozen_moment,
            exemption_snapshot=exemption_snapshot,
        )

        mismatches = self._diff(stored, recomputed)
        consistent = not mismatches
        if not consistent:
            raise PolicyVersionConflict(
                f"复现失败：重算结论与历史记录不一致 ({decision_id})",
                {"decision_id": decision_id, "mismatches": mismatches},
            )
        logger.info(
            "replay ok decision_id=%s policy=%s@v%s action=%s",
            decision_id,
            stored.policy_name,
            stored.policy_version,
            stored.action.value,
        )
        return {
            "consistent": consistent,
            "decision_id": decision_id,
            "policy_name": stored.policy_name,
            "policy_version": stored.policy_version,
            "policy_fingerprint": stored.policy_fingerprint,
            "stored": self._decision_public(stored),
            "recomputed": self._decision_public(recomputed),
        }

    # ---- internal ----

    def _select_policy(self, name: str, version: int | None) -> Policy:
        policy = self._policies.get(name, version) if version is not None else self._policies.latest(name)
        if policy is None:
            raise PolicyDocumentError(
                f"策略不存在: {name}" + (f"@v{version}" if version is not None else "（尚无任何版本）"),
                {"policy_name": name, "policy_version": version},
            )
        return policy

    def _evaluate(
        self,
        resource: dict[str, Any],
        policy: Policy,
        idempotency_key: str | None,
        *,
        decision_id: str | None = None,
        decided_at: str | None = None,
        moment=None,
        exemption_snapshot: dict[str, str] | None = None,
    ) -> Decision:
        moment = moment or self._clock.now()
        hits: list[RuleHit] = []
        violations: list[RuleHit] = []  # 未豁免的 deny 违规
        warnings: list[RuleHit] = []    # warn 规则或被豁免的违规

        for rule in policy.rules:
            if not resource_matches(resource, rule.match):
                continue
            hit = self._eval_rule(
                resource, rule, moment, exemption_snapshot=exemption_snapshot
            )
            hits.append(hit)
            if hit.verdict is Verdict.VIOLATION:
                if hit.exempted or rule.on_violation == "warn":
                    warnings.append(hit)
                else:
                    violations.append(hit)

        if violations:
            action = Action.DENY
            top = max(violations, key=lambda h: _SEVERITY_ORDER.index(h.severity))
            rationale = (
                f"拒绝：命中 {len(violations)} 条未豁免违规"
                f"（最高严重级别 {top.severity.value}，规则 {top.rule_id}）；"
                f"另有 {len(warnings)} 条告警/豁免"
            )
        elif warnings:
            action = Action.ALLOW_WITH_WARNING
            top = max(warnings, key=lambda h: _SEVERITY_ORDER.index(h.severity))
            rationale = (
                f"放行但告警：{len(warnings)} 条命中"
                f"（最高严重级别 {top.severity.value}，"
                + ("均已豁免或为告警规则" )
                + "）"
            )
        else:
            action = Action.ALLOW
            rationale = f"放行：{len(hits)} 条适用规则全部通过"

        return Decision(
            decision_id=decision_id or uuid.uuid4().hex,
            idempotency_key=idempotency_key,
            resource_ref=resource_ref(resource),
            resource_fingerprint=resource_fingerprint(resource),
            policy_name=policy.name,
            policy_version=policy.version,
            policy_fingerprint=policy.fingerprint,
            action=action,
            hits=tuple(hits),
            rationale=rationale,
            decided_at=decided_at or to_iso(moment),
        )

    def _eval_rule(
        self,
        resource: dict[str, Any],
        rule: Rule,
        moment,
        *,
        exemption_snapshot: dict[str, str] | None = None,
    ) -> RuleHit:
        raw_value = get_field_value(resource, rule.field)
        field_exists = not is_missing(raw_value)
        actual = None if not field_exists else raw_value

        try:
            violated = not evaluate(rule.operator, actual, rule.value)
        except Exception as exc:  # 解析期已校验；运行期兜底，绝不静默
            from .errors import UnsupportedRuleError

            if isinstance(exc, UnsupportedRuleError):
                raise
            raise StorageError(f"规则 {rule.id} 判定执行失败: {exc}") from exc

        if not violated:
            return RuleHit(
                rule_id=rule.id,
                verdict=Verdict.PASS,
                severity=rule.severity,
                field=rule.field,
                operator=rule.operator,
                expected=rule.value,
                actual=actual,
                reason=(
                    f"字段 {rule.field}={actual!r} 满足 {rule.operator} {rule.value!r}"
                    if field_exists
                    else f"字段 {rule.field} 缺失，按算子 {rule.operator} 判定为通过"
                ),
            )

        # 违规：采纳豁免。复现模式直接采用历史快照；否则实时查询当前有效豁免。
        exempting_id: str | None = None
        if exemption_snapshot is not None:
            exempting_id = exemption_snapshot.get(rule.id)
        else:
            active = self._exemptions.applicable(resource, rule.id, moment)
            if active:
                exempting_id = active[0].exemption_id

        if exempting_id is not None:
            return RuleHit(
                rule_id=rule.id,
                verdict=Verdict.VIOLATION,
                severity=rule.severity,
                field=rule.field,
                operator=rule.operator,
                expected=rule.value,
                actual=actual,
                reason=(
                    f"命中违规：字段 {rule.field}={actual!r} 不满足 "
                    f"{rule.operator} {rule.value!r}；已被豁免 {exempting_id} 采纳"
                ),
                exempted=True,
                exemption_id=exempting_id,
            )

        return RuleHit(
            rule_id=rule.id,
            verdict=Verdict.VIOLATION,
            severity=rule.severity,
            field=rule.field,
            operator=rule.operator,
            expected=rule.value,
            actual=actual,
            reason=(
                f"命中违规：字段 {rule.field}={'<缺失>' if not field_exists else actual!r} "
                f"不满足 {rule.operator} {rule.value!r}，且无有效豁免"
            ),
        )

    @staticmethod
    def _diff(stored: Decision, recomputed: Decision) -> list[str]:
        mismatches: list[str] = []
        comparable = (
            "resource_ref",
            "resource_fingerprint",
            "policy_name",
            "policy_version",
            "policy_fingerprint",
            "action",
            "rationale",
        )
        for attr in comparable:
            if getattr(stored, attr) != getattr(recomputed, attr):
                mismatches.append(
                    f"{attr}: stored={getattr(stored, attr)!r} "
                    f"recomputed={getattr(recomputed, attr)!r}"
                )
        if len(stored.hits) != len(recomputed.hits):
            mismatches.append(
                f"hits length: stored={len(stored.hits)} recomputed={len(recomputed.hits)}"
            )
        else:
            for i, (a, b) in enumerate(zip(stored.hits, recomputed.hits)):
                for attr in (
                    "rule_id",
                    "verdict",
                    "severity",
                    "field",
                    "operator",
                    "expected",
                    "actual",
                    "exempted",
                    "exemption_id",
                ):
                    if getattr(a, attr) != getattr(b, attr):
                        mismatches.append(f"hits[{i}].{attr}: stored={getattr(a, attr)!r} recomputed={getattr(b, attr)!r}")
        return mismatches

    @staticmethod
    def _decision_public(decision: Decision) -> dict[str, Any]:
        return {
            "decision_id": decision.decision_id,
            "resource_ref": decision.resource_ref,
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
                    "actual": h.actual,
                    "expected": h.expected,
                    "exempted": h.exempted,
                    "exemption_id": h.exemption_id,
                    "reason": h.reason,
                }
                for h in decision.hits
            ],
        }
