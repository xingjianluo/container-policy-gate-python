"""版本可复现：历史结论按发生时的策略版本与内容指纹回放，不被后续重算覆盖。"""
from __future__ import annotations

import logging

import pytest

from policygate.exceptions import IdempotencyConflictError
from policygate.models import RejectReason

logger = logging.getLogger("policygate.tests")


def test_replay_reproduces_historical_version_and_fingerprint(service):
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": "g", "namespace": "app"},
           "spec": {"image_repository": "gcr.io", "cpu_limit": "1"}}
    v1 = service.admit(pod, idempotency_key="hist-v1", policy_version="v1")["result"]
    # v2 收紧白名单
    v2 = service.admit(pod, idempotency_key="hist-v2", policy_version="v2")["result"]
    assert v1["decision"] == "pass" and v2["decision"] == "reject"

    replayed = service.replay("Pod/app/g", "hist-v1")["result"]
    logger.info(
        "复现输入资源=%s 历史策略版本=%s 历史指纹=%s 复现结论=%s 历史依据=%s",
        "Pod/app/g", replayed["policy_version"], replayed["policy_fingerprint"],
        replayed["decision"], [f["evidence"] for f in replayed["findings"]],
    )
    assert replayed["replay"] is True
    assert replayed["policy_version"] == "v1"
    assert replayed["policy_fingerprint"] == v1["policy_fingerprint"]
    assert replayed["decision"] == "pass"
    assert replayed["resource_fingerprint"] == v1["resource_fingerprint"]


def test_replay_latest_when_record_id_omitted(service):
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": "g", "namespace": "app"},
           "spec": {"image_repository": "gcr.io", "cpu_limit": "1"}}
    service.admit(pod, idempotency_key="a", policy_version="v1")
    service.admit(pod, idempotency_key="b", policy_version="v2")
    replayed = service.replay("Pod/app/g")["result"]
    assert replayed["policy_version"] == "v2"


def test_replay_unknown_record_is_distinguishable_error(service):
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": "x", "namespace": "app"},
           "spec": {"image_repository": "gcr.io", "cpu_limit": "1"}}
    service.admit(pod, idempotency_key="exists", policy_version="v1")
    with pytest.raises(IdempotencyConflictError) as exc:
        service.replay("Pod/app/x", "missing")
    assert exc.value.reason == RejectReason.RECORD_NOT_FOUND


def test_history_lists_all_versions_with_fingerprints(service):
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": "g", "namespace": "app"},
           "spec": {"image_repository": "gcr.io", "cpu_limit": "1"}}
    service.admit(pod, idempotency_key="h1", policy_version="v1")
    service.admit(pod, idempotency_key="h2", policy_version="v2")
    history = service.history("Pod/app/g")
    versions = {item["result"]["policy_version"] for item in history}
    assert versions == {"v1", "v2"}
    fps = {item["result"]["policy_fingerprint"] for item in history}
    assert len(fps) == 2  # 两个版本的内容指纹不同且都被保留
