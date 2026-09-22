"""豁免：生效范围、有效期、状态机、幂等。"""

from __future__ import annotations

import logging

import pytest

from app.clock import to_iso
from app.errors import (
    ExemptionExpired,
    ExemptionNotFound,
    ExemptionOutOfScope,
    IllegalStateTransition,
    PolicyDocumentError,
)
from app.exemption import ExemptionStatus
from app.models import Action

from .conftest import bad_resource

log = logging.getLogger("test.exemption")


def _request_approved(container, *, scope=None, rule_ids=("image-fixed-tag",),
                      start_shift=(-3600), end_shift=3600, key="ex1"):
    clock = container.clock
    now = clock.now()
    from datetime import timedelta

    payload = {
        "scope": scope if scope is not None else {"kind": "Deployment", "namespace": "prod"},
        "rule_ids": list(rule_ids),
        "valid_from": to_iso(now + timedelta(seconds=start_shift)),
        "valid_until": to_iso(now + timedelta(seconds=end_shift)),
        "reason": "release window",
        "idempotency_key": key,
    }
    ex = container.exemption_service.request(payload)
    return container.exemption_service.approve(ex.exemption_id)


def test_valid_exemption_downgrades_deny_to_warning(container, published_policy):
    ex = _request_approved(container)
    decision = container.evaluator.admit(bad_resource(), "default", idempotency_key="d1")
    assert decision.action is Action.ALLOW_WITH_WARNING
    hit = next(h for h in decision.hits if h.rule_id == "image-fixed-tag")
    assert hit.exempted is True
    assert hit.exemption_id == ex.exemption_id
    assert ex.exemption_id in hit.reason
    log.info("豁免生效 输入=%s 豁免=%s 依据=%s", decision.resource_ref,
             ex.exemption_id[:8], hit.reason)


def test_out_of_scope_namespace_exemption_not_adopted(container, published_policy):
    _request_approved(container, scope={"kind": "Deployment", "namespace": "staging"})
    decision = container.evaluator.admit(bad_resource(), "default", idempotency_key="d2")
    assert decision.action is Action.DENY
    hit = next(h for h in decision.hits if h.rule_id == "image-fixed-tag")
    assert hit.exempted is False
    log.info("越界豁免未被采纳 输入=%s(ns=prod) 豁免范围=ns=staging -> %s",
             decision.resource_ref, decision.action.value)


def test_out_of_scope_name_and_rule_filtering(container, published_policy):
    # scope 名字不匹配
    _request_approved(
        container, scope={"kind": "Deployment", "namespace": "prod", "name": "other"}, key="a"
    )
    d = container.evaluator.admit(bad_resource(), "default", idempotency_key="d3")
    assert d.action is Action.DENY

    # rule_ids 不覆盖命中的规则
    _request_approved(container, rule_ids=("resources-limits-present",), key="b")
    d2 = container.evaluator.admit(bad_resource(), "default", idempotency_key="d4")
    assert d2.action is Action.DENY
    hit = next(h for h in d2.hits if h.rule_id == "image-fixed-tag")
    assert hit.exempted is False


def test_label_scope_matching(container, published_policy):
    _request_approved(
        container,
        scope={"kind": "Deployment", "namespace": "prod", "labels": {"app": "web"}},
        key="lbl",
    )
    d = container.evaluator.admit(bad_resource(), "default", idempotency_key="d5")
    assert d.action is Action.ALLOW_WITH_WARNING


def test_expired_exemption_not_adopted(container, published_policy):
    from datetime import timedelta

    now = container.clock.now()
    ex = container.exemption_service.request(
        {
            "scope": {"kind": "Deployment", "namespace": "prod"},
            "rule_ids": ["image-fixed-tag"],
            "valid_from": to_iso(now - timedelta(hours=2)),
            "valid_until": to_iso(now - timedelta(hours=1)),  # 已过期
            "reason": "old window",
        }
    )
    container.exemption_service.approve(ex.exemption_id)
    d = container.evaluator.admit(bad_resource(), "default", idempotency_key="d6")
    assert d.action is Action.DENY
    log.info("过期豁免未被采纳 valid_until 在判定时刻之前 -> %s", d.action.value)

    # 显式采纳校验必须抛可区分的 ExemptionExpired
    with pytest.raises(ExemptionExpired) as exc:
        container.exemption_service.check_adoption(
            ex.exemption_id, bad_resource(), "image-fixed-tag", now
        )
    assert exc.value.code == "exemption_expired"


def test_not_yet_valid_exemption_not_adopted(container, published_policy):
    from datetime import timedelta

    now = container.clock.now()
    ex = container.exemption_service.request(
        {
            "scope": {"kind": "Deployment", "namespace": "prod"},
            "rule_ids": ["image-fixed-tag"],
            "valid_from": to_iso(now + timedelta(hours=1)),  # 明天才生效
            "valid_until": to_iso(now + timedelta(hours=2)),
            "reason": "future window",
        }
    )
    container.exemption_service.approve(ex.exemption_id)
    d = container.evaluator.admit(bad_resource(), "default", idempotency_key="d7")
    assert d.action is Action.DENY


def test_check_adoption_distinguishes_scope_and_time(container, published_policy):
    from datetime import timedelta

    now = container.clock.now()
    # 已过期 + 范围也不对：先判时间
    ex = container.exemption_service.request(
        {
            "scope": {"namespace": "staging"},
            "rule_ids": [],
            "valid_from": to_iso(now - timedelta(hours=2)),
            "valid_until": to_iso(now - timedelta(hours=1)),
            "reason": "x",
        }
    )
    container.exemption_service.approve(ex.exemption_id)
    with pytest.raises(ExemptionExpired):
        container.exemption_service.check_adoption(
            ex.exemption_id, bad_resource(), "image-fixed-tag", now
        )

    # 时间有效但范围越界 -> ExemptionOutOfScope，code 与过期不同
    ex2 = container.exemption_service.request(
        {
            "scope": {"namespace": "staging"},
            "rule_ids": [],
            "valid_from": to_iso(now - timedelta(hours=1)),
            "valid_until": to_iso(now + timedelta(hours=1)),
            "reason": "x",
            "idempotency_key": "scope-only",
        }
    )
    container.exemption_service.approve(ex2.exemption_id)
    with pytest.raises(ExemptionOutOfScope) as exc:
        container.exemption_service.check_adoption(
            ex2.exemption_id, bad_resource(), "image-fixed-tag", now
        )
    assert exc.value.code == "exemption_out_of_scope"


def test_unapproved_exemption_cannot_be_adopted(container, published_policy):
    # requested 但未 approve
    from datetime import timedelta

    now = container.clock.now()
    created = container.exemption_service.request(
        {
            "scope": {"kind": "Deployment", "namespace": "prod"},
            "rule_ids": ["image-fixed-tag"],
            "valid_from": to_iso(now - timedelta(hours=1)),
            "valid_until": to_iso(now + timedelta(hours=1)),
            "reason": "pending",
        }
    )
    assert created.status is ExemptionStatus.REQUESTED
    d = container.evaluator.admit(bad_resource(), "default", idempotency_key="d8")
    assert d.action is Action.DENY
    with pytest.raises(IllegalStateTransition):
        container.exemption_service.check_adoption(
            created.exemption_id, bad_resource(), "image-fixed-tag", now
        )


def test_exemption_state_machine_rejects_illegal_transitions(container):
    from datetime import timedelta

    now = container.clock.now()
    ex = container.exemption_service.request(
        {
            "scope": {},
            "rule_ids": [],
            "valid_from": to_iso(now - timedelta(hours=1)),
            "valid_until": to_iso(now + timedelta(hours=1)),
            "reason": "x",
        }
    )
    # requested 不能直接 revoked
    with pytest.raises(IllegalStateTransition) as exc:
        container.exemption_service.revoke(ex.exemption_id)
    assert exc.value.code == "illegal_state_transition"
    assert exc.value.details["from"] == "requested"

    approved = container.exemption_service.approve(ex.exemption_id)
    assert approved.status is ExemptionStatus.APPROVED

    # approved 不能重复 approve，也不能 reject
    with pytest.raises(IllegalStateTransition):
        container.exemption_service.approve(ex.exemption_id)
    with pytest.raises(IllegalStateTransition):
        container.exemption_service.reject(ex.exemption_id)

    revoked = container.exemption_service.revoke(ex.exemption_id)
    assert revoked.status is ExemptionStatus.REVOKED
    # revoked 是终态
    with pytest.raises(IllegalStateTransition):
        container.exemption_service.approve(ex.exemption_id)


def test_revoked_exemption_no_longer_applies(container, published_policy):
    ex = _request_approved(container, key="rev")
    container.exemption_service.revoke(ex.exemption_id)
    d = container.evaluator.admit(bad_resource(), "default", idempotency_key="d9")
    assert d.action is Action.DENY


def test_exemption_request_is_idempotent(container):
    from datetime import timedelta

    now = container.clock.now()
    payload = {
        "scope": {"kind": "Deployment"},
        "rule_ids": [],
        "valid_from": to_iso(now - timedelta(hours=1)),
        "valid_until": to_iso(now + timedelta(hours=1)),
        "reason": "same",
        "idempotency_key": "same-key",
    }
    first = container.exemption_service.request(payload)
    second = container.exemption_service.request(payload)
    assert first.exemption_id == second.exemption_id
    data = container.exemption_json_store.load()
    assert len(data["exemptions"]) == 1


def test_exemption_validation_errors(container):
    with pytest.raises(PolicyDocumentError):
        container.exemption_service.request(
            {"scope": {"weird": 1}, "valid_from": "2026-09-23T09:00:00Z",
             "valid_until": "2026-09-23T11:00:00Z"}
        )
    with pytest.raises(PolicyDocumentError):
        container.exemption_service.request(
            {"scope": {}, "valid_from": "2026-09-23T12:00:00Z",
             "valid_until": "2026-09-23T11:00:00Z"}  # 倒置
        )
    with pytest.raises(PolicyDocumentError):
        container.exemption_service.request(
            {"scope": {}, "valid_from": "not-a-date",
             "valid_until": "2026-09-23T11:00:00Z"}
        )


def test_get_missing_exemption_404(container):
    with pytest.raises(ExemptionNotFound) as exc:
        container.exemption_service.get("nope")
    assert exc.value.code == "exemption_not_found"
