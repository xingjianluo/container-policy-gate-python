"""豁免：生效范围、有效期、状态流转、重复提交。"""
from __future__ import annotations

import logging
import uuid

import pytest

from policygate.exceptions import (
    ExemptionError,
    IllegalTransitionError,
    ResourceValidationError,
)
from policygate.models import RejectReason

logger = logging.getLogger("policygate.tests")

POD_BAD = {
    "apiVersion": "v1", "kind": "Pod",
    "metadata": {"name": "evil", "namespace": "app"},
    "spec": {"image_repository": "docker.io/evil"},
}


def _exemption(eid="EX-1", **overrides):
    payload = {
        "id": eid, "rule_ids": ["R-IMAGE-REGISTRY"], "kinds": ["Pod"],
        "namespaces": ["app"],
        "valid_from": "2026-09-01T00:00:00Z",
        "valid_until": "2026-12-31T00:00:00Z",
        "reason": "迁移期豁免",
    }
    payload.update(overrides)
    return payload


def _admit_and_log(service, manifest, key=None):
    key = key or f"ex-test-{uuid.uuid4().hex[:10]}"
    out = service.admit(manifest, idempotency_key=key)
    r = out["result"]
    logger.info(
        "豁免评估 输入=%s 策略版本=%s 结论=%s 命中豁免=%s 依据=%s",
        manifest, r["policy_version"], r["decision"],
        [f["exempted_by"] for f in r["findings"]],
        [f["evidence"] for f in r["findings"]],
    )
    return r


def test_pending_exemption_does_not_take_effect(service):
    service.submit_exemption(_exemption(), idempotency_key="k-ex")
    result = _admit_and_log(service, POD_BAD)
    assert result["decision"] == "reject"
    assert all(f["exempted_by"] is None for f in result["findings"])


def test_active_exemption_exempts_matched_finding_only(service):
    service.submit_exemption(_exemption(), idempotency_key="k-ex")
    service.transition_exemption("EX-1", "activate")
    result = _admit_and_log(service, POD_BAD)
    # reject 级别的镜像规则被豁免；cpu_limit 的 warn 未被豁免
    img = next(f for f in result["findings"] if f["rule_id"] == "R-IMAGE-REGISTRY")
    cpu = next(f for f in result["findings"] if f["rule_id"] == "R-CPU-LIMIT")
    assert img["exempted_by"] == "EX-1"
    assert cpu["exempted_by"] is None
    assert result["decision"] == "warn"  # 无未豁免 reject 项


def test_scope_mismatch_namespace_exemption_not_applied(service):
    service.submit_exemption(
        _exemption(namespaces=["kube-system"]), idempotency_key="k-ex")
    service.transition_exemption("EX-1", "activate")
    chk = service.check_exemption({"exemption_id": "EX-1", "resource": POD_BAD})
    assert chk["reason_code"] == "exemption_scope_mismatch"
    result = _admit_and_log(service, POD_BAD)
    assert result["decision"] == "reject"


def test_scope_mismatch_rule_id_exemption_not_applied(service):
    # 豁免只覆盖 CPU 规则，镜像 reject 规则仍然拒绝
    service.submit_exemption(_exemption(rule_ids=["R-CPU-LIMIT"]), idempotency_key="k-ex")
    service.transition_exemption("EX-1", "activate")
    result = _admit_and_log(service, POD_BAD)
    assert result["decision"] == "reject"
    img = next(f for f in result["findings"] if f["rule_id"] == "R-IMAGE-REGISTRY")
    assert img["exempted_by"] is None


def test_expired_exemption_not_applied(service):
    service.submit_exemption(
        _exemption(valid_from="2025-01-01T00:00:00Z",
                   valid_until="2025-02-01T00:00:00Z"),
        idempotency_key="k-ex")
    service.transition_exemption("EX-1", "activate")
    chk = service.check_exemption({"exemption_id": "EX-1", "resource": POD_BAD})
    assert chk["reason_code"] == "exemption_expired"
    result = _admit_and_log(service, POD_BAD)
    assert result["decision"] == "reject"


def test_not_yet_valid_exemption_not_applied(service):
    service.submit_exemption(
        _exemption(valid_from="2027-01-01T00:00:00Z",
                   valid_until="2027-12-31T00:00:00Z"),
        idempotency_key="k-ex")
    service.transition_exemption("EX-1", "activate")
    chk = service.check_exemption({"exemption_id": "EX-1", "resource": POD_BAD})
    assert chk["reason_code"] == "exemption_not_yet_valid"


def test_revoked_exemption_not_applied(service):
    service.submit_exemption(_exemption(), idempotency_key="k-ex")
    service.transition_exemption("EX-1", "activate")
    service.transition_exemption("EX-1", "revoke")
    chk = service.check_exemption({"exemption_id": "EX-1", "resource": POD_BAD})
    assert chk["reason_code"] == "exemption_not_active"
    result = _admit_and_log(service, POD_BAD)
    assert result["decision"] == "reject"


def test_illegal_transitions_are_rejected(service):
    service.submit_exemption(_exemption(), idempotency_key="k-ex")
    # pending -> revoked 非法
    with pytest.raises(IllegalTransitionError) as exc:
        service.transition_exemption("EX-1", "revoke")
    assert exc.value.reason == RejectReason.ILLEGAL_STATE_TRANSITION
    service.transition_exemption("EX-1", "activate")
    # active -> active 非法
    with pytest.raises(IllegalTransitionError) as exc:
        service.transition_exemption("EX-1", "activate")
    assert exc.value.reason == RejectReason.ILLEGAL_STATE_TRANSITION
    service.transition_exemption("EX-1", "revoke")
    # revoked 终态
    with pytest.raises(IllegalTransitionError):
        service.transition_exemption("EX-1", "activate")


def test_rejected_exemption_is_terminal(service):
    service.submit_exemption(_exemption(), idempotency_key="k-ex")
    service.transition_exemption("EX-1", "reject")
    with pytest.raises(IllegalTransitionError):
        service.transition_exemption("EX-1", "activate")


def test_exemption_idempotent_submit(service):
    payload = _exemption()
    a = service.submit_exemption(payload, idempotency_key="idem-ex")
    b = service.submit_exemption(payload, idempotency_key="idem-ex")
    assert a["id"] == b["id"] and a["status"] == b["status"] == "pending"
    # 不同 key 相同 id 必须冲突拒绝
    with pytest.raises(ExemptionError) as exc:
        service.submit_exemption(payload, idempotency_key="other")
    assert exc.value.reason == RejectReason.DUPLICATE_SUBMISSION_CONFLICT


def test_exemption_missing_fields_rejected(service):
    bad = {"id": "X"}  # 缺有效期
    with pytest.raises(ResourceValidationError):
        service.submit_exemption(bad, idempotency_key="k")


def test_exemption_inverted_window_rejected(service):
    bad = _exemption(valid_from="2027-01-01T00:00:00Z",
                     valid_until="2026-01-01T00:00:00Z")
    with pytest.raises(ResourceValidationError):
        service.submit_exemption(bad, idempotency_key="k")


def test_exemption_without_timezone_rejected(service):
    bad = _exemption(valid_from="2026-09-01 00:00:00",
                     valid_until="2026-12-31 00:00:00")
    with pytest.raises(ResourceValidationError):
        service.submit_exemption(bad, idempotency_key="k")
