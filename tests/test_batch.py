"""批量准入与无幂等标识重复上报收口。

覆盖业务：
- 批量提交：逐条结论 + 命中规则 + 判定依据 + 整批汇总；
- 同一批资源换序提交，汇总与批次标识一致；
- 无幂等标识下同内容重复上报（串行 / 并发 / 整批）自动收口；
- 批次混入不合法资源：单独标记，不拖垮整批、不静默放行；
- 批次执行过程中策略版本变化：整批仍落在同一策略快照；
- 内容或策略版本变化 => 新判定，不错误复用；
- 较大批量（120 条）稳定跑完，不重不漏。
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.models import BATCH_ITEM_DECIDED, BATCH_ITEM_INVALID, Action

from .conftest import bad_resource, good_resource, make_policy_document

log = logging.getLogger("test.batch")


def _named_resource(name: str, *, image: str = "nginx:1.27.0", with_limits: bool = True) -> dict:
    spec: dict = {"image": image}
    if with_limits:
        spec["resources"] = {"limits": {"cpu": "1", "memory": "1Gi"}}
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": "prod", "labels": {"app": name}},
        "spec": spec,
    }


def test_batch_admit_basic_per_item_and_summary(container, published_policy):
    """批量提交：逐条给出结论/命中规则/依据，整批汇总正确，条目可单独复现。"""
    resources = [good_resource(), bad_resource()]
    batch = container.batch_service.admit_batch(resources, "default")

    assert batch.policy_version == 1
    assert len(batch.items) == 2
    by_index = {i.index: i for i in batch.items}
    assert by_index[0].status == BATCH_ITEM_DECIDED
    assert by_index[0].decision.action is Action.ALLOW
    assert by_index[1].decision.action is Action.DENY
    # 命中规则与判定依据随条目返回
    deny_hit = next(
        h for h in by_index[1].decision.hits if h.rule_id == "image-fixed-tag"
    )
    assert deny_hit.verdict.value == "violation"
    assert "latest" in deny_hit.reason or deny_hit.actual == "nginx:latest"

    summary = batch.summary
    assert (summary.total, summary.decided, summary.invalid) == (2, 2, 0)
    assert (summary.allow, summary.deny) == (1, 1)
    assert summary.action is Action.DENY

    # 每条记录之后单独复现仍稳定一致
    for item in batch.items:
        replay = container.evaluator.replay(item.decision.decision_id)
        assert replay["consistent"] is True
    log.info(
        "批量基本语义：策略 v%s fp=%s 汇总=%s",
        batch.policy_version,
        batch.policy_fingerprint[:12],
        summary.rationale,
    )


def test_batch_summary_order_independent(container, published_policy):
    """同一批资源换序提交：批次标识与汇总结果一致。"""
    resources = [_named_resource(f"svc-{i}") for i in range(6)]
    resources[1]["spec"]["image"] = "nginx:latest"  # 一条违规
    resources[4]["spec"]["image"] = "redis:latest"

    first = container.batch_service.admit_batch(resources, "default")
    reordered = list(reversed(resources))
    second = container.batch_service.admit_batch(reordered, "default")

    assert first.batch_id == second.batch_id
    assert second.reused is True
    assert first.summary == second.summary
    # 换序后每个资源拿到的结论不变（按资源指纹对齐）
    first_by_fp = {i.decision.resource_fingerprint: i for i in first.items}
    for item in second.items:
        assert item.decision.decision_id == first_by_fp[item.decision.resource_fingerprint].decision.decision_id
    log.info(
        "换序一致性：batch_id=%s 策略 v%s 汇总 action=%s",
        first.batch_id,
        first.policy_version,
        first.summary.action.value,
    )


def test_batch_mixed_invalid_items(container, published_policy):
    """批次混入不合法资源：单独标记原因，其余照常出结论，整批不失败。"""
    missing_fields = {"kind": "Deployment"}  # 缺 apiVersion/metadata/spec
    not_even_object = "i-am-not-a-resource"
    resources = [good_resource(), missing_fields, not_even_object, bad_resource()]

    batch = container.batch_service.admit_batch(resources, "default")
    by_index = {i.index: i for i in batch.items}

    assert by_index[0].status == BATCH_ITEM_DECIDED
    assert by_index[3].status == BATCH_ITEM_DECIDED
    assert by_index[1].status == BATCH_ITEM_INVALID
    assert by_index[1].error["error"] == "resource_validation_failed"
    assert "missing" in by_index[1].error["details"]
    assert by_index[2].status == BATCH_ITEM_INVALID
    assert by_index[2].error["error"] == "resource_validation_failed"

    summary = batch.summary
    assert summary.invalid == 2
    assert summary.decided == 2
    # 不合法条目未产生判定记录
    assert len(container.decision_store.list_all()) == 2
    log.info(
        "混入不合法资源：invalid=%d 原因=%s / %s；策略 v%s 汇总=%s",
        summary.invalid,
        by_index[1].error["message"],
        by_index[2].error["message"],
        batch.policy_version,
        summary.rationale,
    )


def test_serial_duplicate_reports_without_idempotency_key(container, published_policy):
    """无幂等标识串行重试：同内容同策略版本只产生一条判定，返回可见复用。"""
    first, reused1 = container.evaluator.admit_with_meta(bad_resource(), "default")
    assert reused1 is False
    for _ in range(4):
        again, reused = container.evaluator.admit_with_meta(bad_resource(), "default")
        assert reused is True
        assert again.decision_id == first.decision_id
    assert len(container.decision_store.list_all()) == 1
    log.info(
        "串行重复上报收口：5 次提交 -> 唯一判定 %s 策略 v%s 依据=%s",
        first.decision_id[:8],
        first.policy_version,
        first.rationale,
    )


def test_concurrent_duplicate_reports_without_idempotency_key(container, published_policy):
    """无幂等标识并发重复上报（模拟多个定时任务同时交）：只有一条记录。"""
    n = 16
    barrier = threading.Barrier(n)

    def worker():
        barrier.wait()
        return container.evaluator.admit_with_meta(bad_resource(), "default")

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = [f.result() for f in as_completed([pool.submit(worker) for _ in range(n)])]

    ids = {d.decision_id for d, _ in results}
    assert len(ids) == 1
    assert len(container.decision_store.list_all()) == 1
    assert sum(1 for _, reused in results if not reused) == 1  # 恰好一次真实判定
    log.info("并发重复上报收口：%d 线程同内容 -> 唯一判定 %s", n, ids.pop()[:8])


def test_batch_repeat_submission_no_duplicate_records(container, published_policy):
    """整批重复提交：批次与条目均复用，不产生重复记录，汇总与首次一致。"""
    resources = [_named_resource(f"rep-{i}") for i in range(5)]
    resources[0]["spec"]["image"] = "nginx:latest"

    first = container.batch_service.admit_batch(resources, "default")
    records_after_first = len(container.decision_store.list_all())
    assert records_after_first == 5

    second = container.batch_service.admit_batch(resources, "default")
    assert second.reused is True
    assert second.batch_id == first.batch_id
    assert second.summary == first.summary
    assert len(container.decision_store.list_all()) == records_after_first
    assert len(container.batch_store.list_all()) == 1
    log.info(
        "整批重复提交：batch_id=%s 复用=%s 判定记录数不变=%d",
        second.batch_id,
        second.reused,
        records_after_first,
    )


def test_batch_partial_prior_decisions_no_duplicate_no_missing(container, published_policy):
    """批次里部分条目此前已判过：重复提交整批不产生重复记录、不漏条目。"""
    # 先单条判定其中两个资源（无幂等键）
    pre_existing = [_named_resource("partial-0"), _named_resource("partial-1")]
    for res in pre_existing:
        container.evaluator.admit(res, "default")
    assert len(container.decision_store.list_all()) == 2

    # 整批提交：2 条已判过 + 3 条新资源
    resources = pre_existing + [_named_resource(f"partial-{i}") for i in range(2, 5)]
    batch = container.batch_service.admit_batch(resources, "default")

    assert len(batch.items) == 5  # 不漏
    assert all(i.status == BATCH_ITEM_DECIDED for i in batch.items)
    reused_flags = [i.reused for i in batch.items]
    assert reused_flags[:2] == [True, True]  # 前两条复用既有判定
    assert reused_flags[2:] == [False, False, False]
    # 不重：总记录数 = 2 条既有 + 3 条新增
    assert len(container.decision_store.list_all()) == 5
    log.info(
        "部分已判批次：reused=%s 总记录=%d 策略 v%s",
        reused_flags,
        len(container.decision_store.list_all()),
        batch.policy_version,
    )


def test_concurrent_identical_batches_single_record(container, published_policy):
    """多个进程/线程同时交同一批：批次记录唯一，条目判定不重。"""
    resources = [_named_resource(f"conc-{i}") for i in range(8)]
    n = 8
    barrier = threading.Barrier(n)

    def worker():
        barrier.wait()
        return container.batch_service.admit_batch(resources, "default")

    with ThreadPoolExecutor(max_workers=n) as pool:
        batches = [f.result() for f in as_completed([pool.submit(worker) for _ in range(n)])]

    assert len({b.batch_id for b in batches}) == 1
    assert len(container.batch_store.list_all()) == 1
    assert len(container.decision_store.list_all()) == 8  # 每个资源恰好一条
    summaries = {b.summary for b in batches}
    assert len(summaries) == 1
    log.info(
        "并发同批提交：%d 线程 -> 唯一批次 %s 条目记录=%d",
        n,
        batches[0].batch_id,
        len(container.decision_store.list_all()),
    )


def test_batch_policy_snapshot_isolated_from_mid_batch_publish(
    container, published_policy, monkeypatch
):
    """批次执行过程中发布新版本：整批仍按进入批次时的快照判定。"""
    original = container.evaluator.admit_against_policy
    switched = {"done": False}

    def publish_v2_mid_batch(resource, policy, **kwargs):
        if not switched["done"]:
            switched["done"] = True
            doc2 = make_policy_document(version=2)
            doc2["rules"][0]["severity"] = "critical"  # v2 与 v1 结论措辞不同
            container.policy_store.publish(doc2)
            log.info("批次执行中发布了策略 v2")
        return original(resource, policy, **kwargs)

    monkeypatch.setattr(
        container.evaluator, "admit_against_policy", publish_v2_mid_batch
    )

    resources = [_named_resource(f"snap-{i}", image="nginx:latest") for i in range(6)]
    batch = container.batch_service.admit_batch(resources, "default")

    assert switched["done"] is True  # 确实在批次中途发布了 v2
    assert batch.policy_version == 1
    for item in batch.items:
        assert item.decision.policy_version == 1
        assert item.decision.policy_fingerprint == batch.policy_fingerprint
        hit = next(h for h in item.decision.hits if h.rule_id == "image-fixed-tag")
        assert hit.severity.value == "high"  # 按 v1 的 severity，而非 v2 的 critical
    log.info(
        "快照隔离：整批 %d 条均按策略 v%s fp=%s 判定，不受中途发布的 v2 影响",
        len(batch.items),
        batch.policy_version,
        batch.policy_fingerprint[:12],
    )

    # 批次之后的新提交使用最新版 v2
    later = container.evaluator.admit(_named_resource("snap-after"), "default")
    assert later.policy_version == 2


def test_content_change_is_new_decision(container, published_policy):
    """资源内容有改动 => 新判定，不得复用旧结果。"""
    before = container.evaluator.admit(bad_resource(), "default")
    assert before.action is Action.DENY

    fixed = bad_resource()
    fixed["spec"]["image"] = "nginx:1.27.0"
    fixed["spec"]["resources"] = {"limits": {"cpu": "1"}}
    after = container.evaluator.admit(fixed, "default")

    assert after.decision_id != before.decision_id
    assert after.action is Action.ALLOW
    assert len(container.decision_store.list_all()) == 2
    log.info(
        "内容变更：%s -> 新判定 %s action=%s",
        before.resource_ref,
        after.decision_id[:8],
        after.action.value,
    )


def test_policy_version_change_is_new_decision(container, published_policy):
    """同一份资源，策略版本变化 => 新判定，不得复用旧版本结论。"""
    first = container.evaluator.admit(bad_resource(), "default")
    assert first.policy_version == 1

    doc2 = make_policy_document(version=2)
    doc2["rules"][0]["on_violation"] = "warn"  # v2 降级为告警
    container.policy_store.publish(doc2)

    second = container.evaluator.admit(bad_resource(), "default")
    assert second.decision_id != first.decision_id
    assert second.policy_version == 2
    assert second.action is Action.ALLOW_WITH_WARNING
    assert len(container.decision_store.list_all()) == 2

    # 但 v2 下同内容再交，仍复用 v2 的判定
    third, reused = container.evaluator.admit_with_meta(bad_resource(), "default")
    assert reused is True
    assert third.decision_id == second.decision_id
    assert len(container.decision_store.list_all()) == 2
    log.info(
        "版本变更：v1 判定 %s 不复用到 v2（新判定 %s），v2 内重复提交复用",
        first.decision_id[:8],
        second.decision_id[:8],
    )


def test_large_batch_stable_no_duplicate_no_missing(container, published_policy):
    """较大批量（120 条不同内容）稳定跑完：不重不漏，重复提交整批复用。"""
    n = 120
    resources = []
    for i in range(n):
        image = "nginx:latest" if i % 3 == 0 else "nginx:1.27.0"
        resources.append(_named_resource(f"bulk-{i}", image=image, with_limits=i % 2 == 0))

    batch = container.batch_service.admit_batch(resources, "default")
    summary = batch.summary
    assert summary.total == n
    assert summary.decided == n
    assert summary.invalid == 0
    assert summary.deny == n // 3  # 每 3 条一条 latest 违规
    assert summary.allow + summary.allow_with_warning + summary.deny == n

    # 每个资源恰好一条判定记录，不重不漏
    decisions = container.decision_store.list_all()
    assert len(decisions) == n
    assert len({d.resource_fingerprint for d in decisions}) == n

    # 整批重复提交：复用首次批次，记录数不变，汇总一致
    again = container.batch_service.admit_batch(resources, "default")
    assert again.reused is True
    assert again.batch_id == batch.batch_id
    assert again.summary == summary
    assert len(container.decision_store.list_all()) == n
    log.info(
        "大批量：%d 条 -> deny=%d warn=%d allow=%d 策略 v%s；重复提交复用 batch=%s",
        n,
        summary.deny,
        summary.allow_with_warning,
        summary.allow,
        batch.policy_version,
        again.batch_id,
    )


def test_batch_http_endpoint(client):
    """HTTP 端到端：批量提交、不合法条目标记、重复提交复用、按 ID 查询批次。"""
    assert client.post("/api/policies", json={"document": make_policy_document()}).status_code == 200

    payload = {
        "resources": [good_resource(), {"kind": "Pod"}, bad_resource()],
        "policy_name": "default",
    }
    r = client.post("/api/admit/batch", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["policy"]["version"] == 1
    assert body["reused"] is False
    assert body["summary"]["total"] == 3
    assert body["summary"]["invalid"] == 1
    items = {i["index"]: i for i in body["items"]}
    assert items[0]["decision"]["action"] == "allow"
    assert items[1]["status"] == "invalid"
    assert items[1]["error"]["error"] == "resource_validation_failed"
    assert items[2]["decision"]["action"] == "deny"
    assert items[2]["decision"]["hits"]  # 命中规则与依据随响应返回

    # 重复提交同一批：复用首次结论
    r2 = client.post("/api/admit/batch", json=payload)
    assert r2.json()["reused"] is True
    assert r2.json()["batch_id"] == body["batch_id"]
    assert r2.json()["summary"] == body["summary"]

    # 按批次 ID 查询
    r3 = client.get(f"/api/batches/{body['batch_id']}")
    assert r3.status_code == 200
    assert r3.json()["summary"] == body["summary"]

    # 单条重复上报（无幂等键）：HTTP 层可见内容复用标记
    a1 = client.post("/api/admit", json={"resource": good_resource()}).json()
    a2 = client.post("/api/admit", json={"resource": good_resource()}).json()
    assert a1["decision_id"] == a2["decision_id"]
    assert a2["content_reused"] is True
    log.info(
        "HTTP 批量：batch=%s 策略 v%s 汇总=%s",
        body["batch_id"],
        body["policy"]["version"],
        body["summary"]["rationale"],
    )
