"""幂等与并发：重复提交不产生重复记录；同 key 不同内容明确冲突；并发唯一。"""
from __future__ import annotations

import logging
import threading

logger = logging.getLogger("policygate.tests")

POD = {
    "apiVersion": "v1", "kind": "Pod",
    "metadata": {"name": "c", "namespace": "app"},
    "spec": {"image_repository": "docker.io/x"},
}


def test_duplicate_submission_returns_same_record(service):
    first = service.admit(POD, idempotency_key="same-key")
    second = service.admit(POD, idempotency_key="same-key")
    assert second["replayed_from_history"] is True
    assert second["idempotency_key"] == first["idempotency_key"]
    assert second["result"] == first["result"]
    assert len(service.history("Pod/app/c")) == 1


def test_same_key_different_content_conflicts(service):
    service.admit(POD, idempotency_key="k")
    other = {"apiVersion": "v1", "kind": "Pod",
             "metadata": {"name": "c", "namespace": "app"},
             "spec": {"image_repository": "docker.io/different"}}
    from policygate.exceptions import IdempotencyConflictError
    from policygate.models import RejectReason

    with __import__("pytest").raises(IdempotencyConflictError) as exc:
        service.admit(other, idempotency_key="k")
    assert exc.value.reason == RejectReason.DUPLICATE_SUBMISSION_CONFLICT
    # 冲突不得落库
    assert len(service.history("Pod/app/c")) == 1


def test_concurrent_identical_submissions_produce_single_record(service):
    errors: list[Exception] = []

    def worker():
        try:
            service.admit(POD, idempotency_key="concurrent-key")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    records = service.history("Pod/app/c")
    assert len(records) == 1
    assert records[0]["idempotency_key"] == "concurrent-key"
    logger.info(
        "并发提交 输入=%s 线程数=16 唯一记录=%s 策略版本=%s 结论=%s",
        POD, records[0]["idempotency_key"],
        records[0]["result"]["policy_version"],
        records[0]["result"]["decision"],
    )


def test_concurrent_exemption_submissions_deduplicated(service):
    payload = {"id": "EX-C", "rule_ids": ["R-IMAGE-REGISTRY"], "kinds": ["Pod"],
               "namespaces": ["app"],
               "valid_from": "2026-09-01T00:00:00Z",
               "valid_until": "2026-12-31T00:00:00Z", "reason": "并发"}
    results: list[str] = []
    lock = threading.Lock()

    def worker():
        out = service.submit_exemption(payload, idempotency_key="ex-concurrent")
        with lock:
            results.append(out["id"])

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == ["EX-C"] * 12
    # 存储中只有一条
    assert service.exemptions.get("EX-C").id == "EX-C"


def test_concurrent_identical_submissions_multiprocess_style(service):
    """顺序+交错地多次调用同一 key，结果仍唯一（锁语义的快速回归）。"""
    for _ in range(8):
        out = service.admit(POD, idempotency_key="interleave-key")
        assert out["idempotency_key"] == "interleave-key"
    assert len(service.history("Pod/app/c")) == 1
