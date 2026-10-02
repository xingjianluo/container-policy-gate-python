"""并发与幂等：重复提交不产生重复记录，并发下最终状态唯一。"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import timedelta

from app.clock import to_iso
from app.errors import IllegalStateTransition
from app.models import Action

from .conftest import bad_resource, good_resource

log = logging.getLogger("test.concurrency")


def test_duplicate_admit_same_idempotency_key_single_record(container, published_policy):
    results = []
    for _ in range(5):
        results.append(
            container.evaluator.admit(bad_resource(), "default", idempotency_key="dup-1")
        )
    ids = {d.decision_id for d in results}
    assert len(ids) == 1
    all_records = container.decision_store.list_all()
    assert len(all_records) == 1
    assert results[0].action is Action.DENY
    log.info("同一清单重复提交 5 次 -> 唯一判定 %s", results[0].decision_id[:8])


def test_concurrent_admit_same_key_unique_outcome(container, published_policy):
    outcomes: list = []
    errors: list = []

    def worker():
        try:
            outcomes.append(
                container.evaluator.admit(
                    bad_resource(), "default", idempotency_key="concurrent-1"
                )
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert len(outcomes) == 16
    ids = {d.decision_id for d in outcomes}
    assert len(ids) == 1
    assert len(container.decision_store.list_all()) == 1
    actions = {d.action for d in outcomes}
    assert actions == {Action.DENY}  # 所有线程看到唯一确定的结论
    log.info("16 并发同键提交 -> 唯一 decision=%s action=%s",
             next(iter(ids))[:8], Action.DENY.value)


def test_concurrent_admit_distinct_keys_all_persisted(container, published_policy):
    n = 20
    barrier = threading.Barrier(n)

    def worker(i: int):
        barrier.wait()  # 尽量放大竞争窗口
        return container.evaluator.admit(
            bad_resource(), "default", idempotency_key=f"key-{i}"
        )

    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(worker, i) for i in range(n)]
        decisions = [f.result() for f in as_completed(futures)]

    assert len({d.decision_id for d in decisions}) == n
    assert len(container.decision_store.list_all()) == n
    assert all(d.action is Action.DENY for d in decisions)
    log.info("%d 个不同键并发提交 -> 持久化 %d 条互不重复的判定", n, n)


def test_concurrent_exemption_requests_same_key_unique(container):
    now = container.clock.now()
    payload = {
        "scope": {"kind": "Deployment"},
        "rule_ids": [],
        "valid_from": to_iso(now - timedelta(hours=1)),
        "valid_until": to_iso(now + timedelta(hours=1)),
        "reason": "race",
        "idempotency_key": "ex-race",
    }
    n = 12
    barrier = threading.Barrier(n)

    def worker():
        barrier.wait()
        return container.exemption_service.request(payload)

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = [f.result() for f in as_completed([pool.submit(worker) for _ in range(n)])]

    ids = {e.exemption_id for e in results}
    assert len(ids) == 1
    data = container.exemption_json_store.load()
    assert len(data["exemptions"]) == 1
    log.info("12 并发同键豁免申请 -> 唯一豁免 %s", ids.pop()[:8])


def test_concurrent_state_transitions_only_one_succeeds(container):
    """对同一豁免并发 approve/reject：只有一个方向成功，另一个被明确拒绝。"""
    now = container.clock.now()
    ex = container.exemption_service.request(
        {
            "scope": {},
            "rule_ids": [],
            "valid_from": to_iso(now - timedelta(hours=1)),
            "valid_until": to_iso(now + timedelta(hours=1)),
            "reason": "race-transition",
        }
    )
    results: dict[str, int] = {"approve": 0, "reject": 0}
    rejected: list[str] = []
    lock = threading.Lock()

    def worker(action: str):
        barrier.wait()
        try:
            if action == "approve":
                container.exemption_service.approve(ex.exemption_id)
            else:
                container.exemption_service.reject(ex.exemption_id)
            with lock:
                results[action] += 1
        except IllegalStateTransition as exc:
            # 竞争失败方必须收到明确的非法流转拒绝
            with lock:
                rejected.append(exc.code)

    barrier = threading.Barrier(8)
    threads = []
    for i in range(8):
        threads.append(threading.Thread(target=worker, args=("approve" if i % 2 == 0 else "reject",)))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    total = results["approve"] + results["reject"]
    assert total == 1  # requested 只能流转一次
    assert len(rejected) == 7
    assert set(rejected) == {"illegal_state_transition"}
    final = container.exemption_service.get(ex.exemption_id)
    assert final.status.value in {"approved", "rejected"}
    log.info("并发状态流转结果: %s 最终状态=%s", results, final.status.value)


def test_no_idempotency_key_same_content_deduped(container, published_policy):
    """无幂等标识时按内容收口：同内容 + 同策略版本重复提交只产生一条记录。"""
    d1 = container.evaluator.admit(bad_resource(), "default")
    d2 = container.evaluator.admit(bad_resource(), "default")
    assert d1.decision_id == d2.decision_id
    assert len(container.decision_store.list_all()) == 1
    log.info("无幂等键同内容重复提交 -> 复用判定 %s", d1.decision_id[:8])


def test_no_idempotency_key_changed_content_new_record(container, published_policy):
    """无幂等标识但内容有改动：必须视为新提交，产生新记录。"""
    d1 = container.evaluator.admit(bad_resource(), "default")
    changed = bad_resource()
    changed["spec"]["image"] = "nginx:1.27.0"  # 内容改动 -> 新判定
    d2 = container.evaluator.admit(changed, "default")
    assert d1.decision_id != d2.decision_id
    assert len(container.decision_store.list_all()) == 2


def test_same_key_different_payload_returns_original(container, published_policy):
    """同幂等键但内容不同：以首次提交为准，后续提交不改变记录（首决确定性）。"""
    first = container.evaluator.admit(bad_resource(), "default", idempotency_key="sticky")
    assert first.action is Action.DENY
    second = container.evaluator.admit(good_resource(), "default", idempotency_key="sticky")
    assert second.decision_id == first.decision_id
    assert second.action is Action.DENY
    assert second.resource_fingerprint == first.resource_fingerprint


def test_replay_under_concurrent_reads(container, published_policy):
    decisions = [
        container.evaluator.admit(bad_resource(), "default", idempotency_key=f"rr-{i}")
        for i in range(8)
    ]
    errors: list = []

    def replay_all():
        try:
            for d in decisions:
                assert container.evaluator.replay(d.decision_id)["consistent"]
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=replay_all) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
