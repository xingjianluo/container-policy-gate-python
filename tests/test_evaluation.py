"""策略评估：结论、命中规则、严重级别与处置可区分；必填字段缺失独立拒绝。"""
from __future__ import annotations

import logging
import uuid

import pytest

from policygate.exceptions import ResourceValidationError
from policygate.models import RejectReason

logger = logging.getLogger("policygate.tests")

POD_GOOD = {
    "apiVersion": "v1", "kind": "Pod",
    "metadata": {"name": "web", "namespace": "app"},
    "spec": {"image_repository": "registry.internal", "cpu_limit": "500m"},
}
POD_BAD_IMAGE = {
    "apiVersion": "v1", "kind": "Pod",
    "metadata": {"name": "evil", "namespace": "app"},
    "spec": {"image_repository": "docker.io/evil"},
}
POD_PRIVILEGED = {
    "apiVersion": "v1", "kind": "Pod",
    "metadata": {"name": "evil", "namespace": "app"},
    "spec": {"image_repository": "registry.internal",
             "cpu_limit": "1", "privileged": True},
}


def _admit(service, manifest, key=None, version=None):
    key = key or f"test-{uuid.uuid4().hex[:12]}"
    out = service.admit(manifest, idempotency_key=key, policy_version=version)
    result = out["result"]
    logger.info(
        "输入=%s 策略版本=%s 策略指纹=%s 结论=%s 处置=%s 命中=%s 依据=%s",
        manifest, result["policy_version"], result["policy_fingerprint"][:19],
        result["decision"], result["action"],
        [f["rule_id"] for f in result["findings"]],
        [f["evidence"] for f in result["findings"]],
    )
    return result


def test_pass_when_no_rule_violated(service):
    result = _admit(service, POD_GOOD, version="v1")
    assert result["decision"] == "pass"
    assert result["action"] == "allow"
    assert result["findings"] == []


def test_reject_finding_carries_severity_decision_and_evidence(service):
    result = _admit(service, POD_BAD_IMAGE, version="v1")
    assert result["decision"] == "reject"
    assert result["action"] == "deny"
    by_id = {f["rule_id"]: f for f in result["findings"]}
    assert by_id["R-IMAGE-REGISTRY"]["severity"] == "critical"
    assert by_id["R-IMAGE-REGISTRY"]["rule_decision"] == "reject"
    assert "docker.io/evil" in by_id["R-IMAGE-REGISTRY"]["evidence"]
    # warn 级别命中不改变 reject 结论，但同样列出
    assert by_id["R-CPU-LIMIT"]["rule_decision"] == "warn"


def test_warn_only_violation_allows_with_warning(service):
    # 镜像合规但缺 cpu_limit：仅 warn 规则命中
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": "w", "namespace": "app"},
           "spec": {"image_repository": "registry.internal"}}
    result = _admit(service, pod, version="v1")
    assert result["decision"] == "warn"
    assert result["action"] == "allow"
    assert len(result["findings"]) == 1


def test_privileged_container_rejected_by_boolean_rule(service):
    result = _admit(service, POD_PRIVILEGED, version="v1")
    assert result["decision"] == "reject"
    assert any(f["rule_id"] == "R-NO-PRIVILEGED" for f in result["findings"])


def test_missing_required_resource_fields_not_silently_allowed(service):
    for bad in (
        {},
        {"kind": "Pod", "metadata": {"name": "x"}},
        {"apiVersion": "v1", "kind": "Pod", "metadata": {}},
        {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": ""}},
    ):
        with pytest.raises(ResourceValidationError) as exc:
            service.admit(bad, idempotency_key=f"bad-{uuid.uuid4().hex[:8]}")
        assert exc.value.reason == RejectReason.RESOURCE_FIELD_MISSING


def test_policy_version_changes_conclusion(service):
    # gcr.io 在 v1 白名单内，v2 收紧后被拒
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": "g", "namespace": "app"},
           "spec": {"image_repository": "gcr.io", "cpu_limit": "1"}}
    v1 = _admit(service, pod, key="gk-v1", version="v1")
    v2 = _admit(service, pod, key="gk-v2", version="v2")
    assert v1["decision"] == "pass"
    assert v2["decision"] == "reject"
    assert v1["policy_fingerprint"] != v2["policy_fingerprint"]


def test_deployment_replicas_rule_only_in_v2(service):
    dep = {"apiVersion": "apps/v1", "kind": "Deployment",
           "metadata": {"name": "d", "namespace": "app"},
           "spec": {"image_repository": "registry.internal", "replicas": 1}}
    v1 = _admit(service, dep, key="dep-v1", version="v1")
    v2 = _admit(service, dep, key="dep-v2", version="v2")
    assert v1["decision"] == "pass"
    assert v2["decision"] == "warn"
    assert v2["findings"][0]["rule_id"] == "R-REPLICAS-MIN"
