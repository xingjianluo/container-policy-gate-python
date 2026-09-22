"""策略评估引擎。

输入：资源 + 某一不可变策略版本 + 当前生效豁免列表 + 评估时刻。
输出：:class:`EvaluationResult`，包含整体结论、逐条命中、严重级别与处置，
以及可供人工复核的判定依据（evidence）。

规则判定结果三态：通过 / 违例（被豁免） / 违例（未豁免）。
只有"未豁免违例"参与整体结论聚合。
"""
from __future__ import annotations

from datetime import datetime

from .exemptions import exemption_applies
from .models import (
    AdmissionAction,
    EvaluationResult,
    Exemption,
    Finding,
    OverallDecision,
    PolicyDocument,
    PolicyRule,
    Resource,
    RuleDecision,
)
from .resources import resource_fingerprint


def _walk(root: dict[str, object], path: str) -> tuple[bool, object]:
    """字段路径相对资源清单根，例如 spec.image_repository。"""
    cur: object = root
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return False, None
    return True, cur


def _rule_violated(rule: PolicyRule, manifest: dict[str, object]) -> tuple[bool, str]:
    """返回 (是否违例, 判定依据)。依据同时描述实际值与期望值。"""
    found, actual = _walk(manifest, rule.field_path)
    op = rule.operator
    expected = rule.expected
    if op == "exists":
        if found:
            return False, f"{rule.field_path} 存在，值={actual!r}"
        return True, f"必需字段 {rule.field_path} 不存在"
    if op == "not_exists":
        if not found:
            return False, f"{rule.field_path} 不存在，符合要求"
        return True, f"禁止字段 {rule.field_path} 存在，值={actual!r}"
    if not found:
        # 字段缺失时：否定类条件（not_equals / not_in）天然满足，
        # 不与"必填字段缺失"混淆；缺失即违例仅由 exists 规则表达。
        if op == "not_equals":
            return False, f"{rule.field_path} 缺失，视为不等于 {expected!r}"
        if op == "not_in":
            return False, f"{rule.field_path} 缺失，视为不属于 {expected!r}"
        return True, f"{rule.field_path} 缺失，无法满足 {op} {expected!r}"
    if op == "equals":
        ok = actual == expected
        return (not ok), f"{rule.field_path}={actual!r}，要求 equals {expected!r}"
    if op == "not_equals":
        ok = actual != expected
        return (not ok), f"{rule.field_path}={actual!r}，要求 not_equals {expected!r}"
    if op == "in":
        ok = actual in expected  # type: ignore[operator]
        return (not ok), f"{rule.field_path}={actual!r}，要求 in {expected!r}"
    if op == "not_in":
        ok = actual not in expected  # type: ignore[operator]
        return (not ok), f"{rule.field_path}={actual!r}，要求 not_in {expected!r}"
    if op == "regex":
        if not isinstance(actual, str):
            return True, f"{rule.field_path}={actual!r} 不是字符串，无法匹配正则"
        import re

        ok = re.search(expected, actual) is not None
        return (not ok), f"{rule.field_path}={actual!r}，要求匹配正则 {expected!r}"
    if op in ("less_than", "greater_than"):
        if isinstance(actual, bool) or not isinstance(actual, (int, float)):
            return True, f"{rule.field_path}={actual!r} 不是数值"
        if op == "less_than":
            ok = actual < expected
        else:
            ok = actual > expected
        return (not ok), f"{rule.field_path}={actual!r}，要求 {op} {expected!r}"
    # 理论不可达：加载期已校验操作符集合。
    return True, f"未知操作符 {op}"


class Evaluator:
    def evaluate(
        self,
        resource: Resource,
        policy: PolicyDocument,
        policy_fingerprint: str,
        active_exemptions: list[Exemption],
        now: datetime,
        replay: bool = False,
        evaluated_at: str | None = None,
    ) -> EvaluationResult:
        findings: list[Finding] = []
        any_unexempted = False
        any_reject = False
        any_exempted = False

        for rule in policy.rules:
            if "*" not in rule.match_kinds and resource.kind not in rule.match_kinds:
                continue
            violated, evidence = _rule_violated(rule, resource.raw)
            if not violated:
                continue
            exemption_id: str | None = None
            for ex in active_exemptions:
                if exemption_applies(ex, resource, rule.id, now):
                    exemption_id = ex.id
                    break
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    rule_decision=rule.on_violation,
                    message=rule.description,
                    evidence=evidence,
                    exempted_by=exemption_id,
                )
            )
            if exemption_id is not None:
                any_exempted = True
                continue
            any_unexempted = True
            if rule.on_violation is RuleDecision.REJECT:
                any_reject = True

        if any_reject:
            decision = OverallDecision.REJECT
            action = AdmissionAction.DENY
        elif any_unexempted:
            decision = OverallDecision.WARN
            action = AdmissionAction.ALLOW
        elif any_exempted:
            decision = OverallDecision.EXEMPTED
            action = AdmissionAction.ALLOW
        else:
            decision = OverallDecision.PASS
            action = AdmissionAction.ALLOW

        return EvaluationResult(
            resource_uid=resource.uid,
            resource_fingerprint=resource_fingerprint(resource),
            policy_version=policy.version,
            policy_fingerprint=policy_fingerprint,
            decision=decision,
            action=action,
            findings=findings,
            evaluated_at=evaluated_at or now.isoformat(),
            replay=replay,
        )
