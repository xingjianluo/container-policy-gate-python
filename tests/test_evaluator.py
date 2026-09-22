"""策略评估：结论、命中规则、判定依据、严重级别与处置分离。"""

from __future__ import annotations

import logging

import pytest

from app.errors import PolicyDocumentError, ResourceValidationError
from app.models import Action, Severity, Verdict

from .conftest import bad_resource, good_resource

log = logging.getLogger("test.evaluator")


def test_clean_resource_is_allowed(container, published_policy):
    decision = container.evaluator.admit(good_resource(), "default", idempotency_key="k1")
    assert decision.action is Action.ALLOW
    assert decision.policy_version == 1
    assert len(decision.policy_fingerprint) == 64
    log.info(
        "输入=%s 命中策略版本=v%s fp=%s 结论=%s 依据=%s",
        decision.resource_ref, decision.policy_version,
        decision.policy_fingerprint[:12], decision.action.value, decision.rationale,
    )
    # 两条规则都适用且都通过
    assert {h.rule_id for h in decision.hits} == {
        "image-fixed-tag",
        "resources-limits-present",
    }
    assert all(h.verdict is Verdict.PASS for h in decision.hits)


def test_violating_resource_is_denied_with_evidence(container, published_policy):
    decision = container.evaluator.admit(bad_resource(), "default", idempotency_key="k2")
    assert decision.action is Action.DENY
    deny_hits = [h for h in decision.hits if h.rule_id == "image-fixed-tag"]
    assert len(deny_hits) == 1
    hit = deny_hits[0]
    assert hit.verdict is Verdict.VIOLATION
    assert hit.severity is Severity.HIGH
    assert hit.exempted is False
    assert hit.actual == "nginx:latest"
    assert "不满足" in hit.reason and "无有效豁免" in hit.reason
    # 严重级别(severity) 与 处置(action) 是两个维度
    assert hit.severity.value != decision.action.value
    log.info(
        "输入=%s 命中策略版本=v%s 结论=%s 命中规则=%s 实际值=%r 依据=%s",
        decision.resource_ref, decision.policy_version, decision.action.value,
        hit.rule_id, hit.actual, hit.reason,
    )


def test_warn_rule_allows_with_warning(container, published_policy):
    """only warn-rule violated -> allow_with_warning。"""
    resource = good_resource()
    resource["spec"]["image"] = "nginx:1.27.0"
    resource["spec"].pop("resources")
    decision = container.evaluator.admit(resource, "default", idempotency_key="k3")
    assert decision.action is Action.ALLOW_WITH_WARNING
    hit = next(h for h in decision.hits if h.rule_id == "resources-limits-present")
    assert hit.verdict is Verdict.VIOLATION
    assert hit.severity is Severity.MEDIUM
    log.info("告警规则输入=%s 结论=%s 依据=%s", decision.resource_ref,
             decision.action.value, hit.reason)


def test_deny_and_warn_both_violated_still_denies(container, published_policy):
    decision = container.evaluator.admit(bad_resource(), "default", idempotency_key="k4")
    assert decision.action is Action.DENY
    assert "最高严重级别" in decision.rationale


def test_missing_resource_fields_never_silently_pass(container, published_policy):
    broken = {"kind": "Deployment", "metadata": {"name": "x"}}
    with pytest.raises(ResourceValidationError) as exc:
        container.evaluator.admit(broken, "default")
    assert exc.value.code == "resource_validation_failed"
    assert set(exc.value.details["missing"]) == {"apiVersion", "spec"}
    # 没有产生任何判定记录 -> 没有静默放行
    assert container.decision_store.list_all() == []


def test_missing_policy_is_rejected_not_allowed(container):
    with pytest.raises(PolicyDocumentError) as exc:
        container.evaluator.admit(good_resource(), "ghost")
    assert exc.value.code == "policy_document_invalid"


def test_explicit_policy_version_selection(container, published_policy):
    doc2 = {**published_policy, "version": 2}
    doc2["rules"] = [
        {**published_policy["rules"][0], "severity": "critical"},
        published_policy["rules"][1],
    ]
    container.policy_store.publish(doc2)

    d1 = container.evaluator.admit(bad_resource(), "default",
                                   policy_version=1, idempotency_key="v1")
    d2 = container.evaluator.admit(bad_resource(), "default",
                                   policy_version=2, idempotency_key="v2")
    assert d1.policy_version == 1 and d2.policy_version == 2
    hit1 = next(h for h in d1.hits if h.rule_id == "image-fixed-tag")
    hit2 = next(h for h in d2.hits if h.rule_id == "image-fixed-tag")
    assert hit1.severity is Severity.HIGH
    assert hit2.severity is Severity.CRITICAL
    log.info("同一输入不同策略版本: v1 severity=%s | v2 severity=%s",
             hit1.severity.value, hit2.severity.value)
    # 两个版本指纹必须不同
    assert d1.policy_fingerprint != d2.policy_fingerprint


def test_selector_match_filters_rules(container):
    doc = {
        "name": "default", "version": 1,
        "rules": [
            {"id": "only-statefulset", "match": {"kind": "StatefulSet"},
             "field": "spec.x", "operator": "present",
             "severity": "high", "on_violation": "deny"},
        ],
    }
    container.policy_store.publish(doc)
    decision = container.evaluator.admit(good_resource(), "default", idempotency_key="sel")
    assert decision.action is Action.ALLOW
    assert decision.hits == ()  # 选择器不匹配 -> 规则不参与判定


def test_decision_contains_full_evidence_for_explainability(container, published_policy):
    decision = container.evaluator.admit(bad_resource(), "default", idempotency_key="ev")
    for hit in decision.hits:
        assert hit.rule_id and hit.field and hit.operator and hit.reason
        assert hit.actual is not None or hit.field
    assert decision.decided_at.endswith("Z") or "+" in decision.decided_at
