"""换序重交：逐条结果必须按本次提交顺序逐位对应。

覆盖业务：
- 同一批资源内容不变、仅换序重交：逐条结果按本次提交顺序排列，
  上游按位置回填结论时不会错位；
- 换序重交仍算同一批：batch_id 与整批汇总与首次一致，不产生
  重复的批次记录与判定记录；
- 边界：批内含内容完全相同的条目、混入不合法条目时，换序/重复
  提交后位置对应关系与汇总都不乱；
- 多个定时任务同时交同一批（顺序还不一样）：各自拿到按自己提交
  顺序排列的逐条结果，批次与判定记录均唯一；
- 内容变更或策略版本变更 => 新批次，不复用。
"""

from __future__ import annotations

import logging
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.models import BATCH_ITEM_DECIDED, BATCH_ITEM_INVALID
from app.resource import fingerprint

from .conftest import make_policy_document

log = logging.getLogger("test.batch_reorder")


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


def _assert_items_align_with_submission(batch, resources) -> None:
    """逐条断言：返回的第 i 条结果对应本次提交的第 i 个资源。"""
    assert len(batch.items) == len(resources)
    for position, (item, raw) in enumerate(zip(batch.items, resources)):
        assert item.index == position, f"第 {position} 位 index 错位: {item.index}"
        assert item.item_fingerprint == fingerprint(raw), (
            f"第 {position} 位条目指纹与本次提交的资源不对应"
        )
        if item.status == BATCH_ITEM_DECIDED:
            assert item.decision.resource_fingerprint == fingerprint(raw)


def test_reordered_resubmit_items_follow_current_submission_order(
    container, published_policy
):
    """换序重交：逐条结果按本次提交顺序排列，位置一一对应。"""
    # 三种结论各一条：放行 / 拒绝 / 告警（缺 limits）
    allow_res = _named_resource("ord-allow")
    deny_res = _named_resource("ord-deny", image="nginx:latest")
    warn_res = _named_resource("ord-warn", with_limits=False)

    first = container.batch_service.admit_batch(
        [allow_res, deny_res, warn_res], "default"
    )
    assert [i.decision.action.value for i in first.items] == [
        "allow",
        "deny",
        "allow_with_warning",
    ]

    # 内容不变，仅换序再交一次
    shuffled = [warn_res, allow_res, deny_res]
    second = container.batch_service.admit_batch(shuffled, "default")

    # 仍算同一批：批次标识与汇总一致，不产生新记录
    assert second.reused is True
    assert second.batch_id == first.batch_id
    assert second.summary == first.summary
    assert len(container.batch_store.list_all()) == 1
    assert len(container.decision_store.list_all()) == 3

    # 逐条结果按本次提交顺序：warn -> allow -> deny，位置一一对应
    assert [i.decision.action.value for i in second.items] == [
        "allow_with_warning",
        "allow",
        "deny",
    ]
    _assert_items_align_with_submission(second, shuffled)
    # 每条拿到的仍是原资源的结论（decision_id 与首次对应位置一致）
    first_by_fp = {i.decision.resource_fingerprint: i.decision.decision_id for i in first.items}
    for item in second.items:
        assert item.decision.decision_id == first_by_fp[item.decision.resource_fingerprint]
    log.info(
        "换序重交：batch=%s 策略 v%s 逐条顺序=%s 汇总=%s",
        second.batch_id,
        second.policy_version,
        [i.decision.action.value for i in second.items],
        second.summary.rationale,
    )


def test_reordered_resubmit_with_invalid_items_keeps_positions(
    container, published_policy
):
    """混入不合法条目时换序重交：不合法条目落在本次提交里它原本的位置。"""
    good = _named_resource("inv-good")
    invalid_obj = {"kind": "Pod"}  # 缺必填字段
    invalid_scalar = "not-a-resource"
    deny_res = _named_resource("inv-deny", image="nginx:latest")

    first = container.batch_service.admit_batch(
        [good, invalid_obj, deny_res, invalid_scalar], "default"
    )
    assert [i.status for i in first.items] == [
        BATCH_ITEM_DECIDED,
        BATCH_ITEM_INVALID,
        BATCH_ITEM_DECIDED,
        BATCH_ITEM_INVALID,
    ]

    # 换序：不合法条目挪到不同位置
    shuffled = [invalid_scalar, deny_res, invalid_obj, good]
    second = container.batch_service.admit_batch(shuffled, "default")

    assert second.reused is True
    assert second.batch_id == first.batch_id
    assert second.summary == first.summary
    # 不合法条目按本次提交位置落位，错误原因跟着条目走
    assert [i.status for i in second.items] == [
        BATCH_ITEM_INVALID,
        BATCH_ITEM_DECIDED,
        BATCH_ITEM_INVALID,
        BATCH_ITEM_DECIDED,
    ]
    assert second.items[0].error["error"] == "resource_validation_failed"
    assert second.items[2].error["error"] == "resource_validation_failed"
    assert second.items[2].error["details"]["missing"]  # 缺字段明细仍在
    assert second.items[1].decision.action.value == "deny"
    assert second.items[3].decision.action.value == "allow"
    _assert_items_align_with_submission(second, shuffled)
    log.info(
        "含不合法条目换序：batch=%s 策略 v%s 逐条状态=%s invalid=%d 依据=%s",
        second.batch_id,
        second.policy_version,
        [i.status for i in second.items],
        second.summary.invalid,
        second.summary.rationale,
    )


def test_reordered_resubmit_with_identical_items(container, published_policy):
    """批内含内容完全相同的条目：换序重交后位置对应与汇总都不乱。"""
    dup = _named_resource("dup-same", image="nginx:latest")
    other = _named_resource("dup-other")

    # 同一资源出现两次（内容完全相同）
    first = container.batch_service.admit_batch([dup, other, dup], "default")
    assert first.summary.total == 3
    assert first.summary.deny == 2
    assert first.summary.allow == 1
    # 内容相同的条目复用同一条判定，判定记录只有 2 条
    assert len(container.decision_store.list_all()) == 2
    assert first.items[0].decision.decision_id == first.items[2].decision.decision_id

    shuffled = [dup, dup, other]
    second = container.batch_service.admit_batch(shuffled, "default")

    assert second.reused is True
    assert second.batch_id == first.batch_id
    assert second.summary == first.summary
    assert len(container.batch_store.list_all()) == 1
    assert len(container.decision_store.list_all()) == 2  # 不产生重复判定
    # 位置对应：deny, deny, allow
    assert [i.decision.action.value for i in second.items] == ["deny", "deny", "allow"]
    _assert_items_align_with_submission(second, shuffled)
    log.info(
        "相同条目换序：batch=%s 策略 v%s 逐条=%s 判定记录数=%d",
        second.batch_id,
        second.policy_version,
        [i.decision.action.value for i in second.items],
        len(container.decision_store.list_all()),
    )


def test_content_change_counts_as_new_batch(container, published_policy):
    """换序但改了其中一条内容 => 新批次，不复用首次结论。"""
    resources = [_named_resource(f"chg-{i}") for i in range(3)]
    first = container.batch_service.admit_batch(resources, "default")

    changed = [resources[2], resources[0], _named_resource("chg-1", image="redis:7")]
    second = container.batch_service.admit_batch(changed, "default")

    assert second.reused is False
    assert second.batch_id != first.batch_id
    assert len(container.batch_store.list_all()) == 2
    _assert_items_align_with_submission(second, changed)
    log.info(
        "内容变更：新批次 %s（首次 %s）策略 v%s",
        second.batch_id,
        first.batch_id,
        second.policy_version,
    )


def test_policy_version_change_counts_as_new_batch(container, published_policy):
    """同一批资源换序提交但策略版本已变 => 新批次，按新版本判定。"""
    resources = [_named_resource(f"ver-{i}", image="nginx:latest") for i in range(3)]
    first = container.batch_service.admit_batch(resources, "default")
    assert first.policy_version == 1
    assert first.summary.deny == 3

    doc2 = make_policy_document(version=2)
    doc2["rules"][0]["on_violation"] = "warn"  # v2 降级为告警
    container.policy_store.publish(doc2)

    shuffled = list(reversed(resources))
    second = container.batch_service.admit_batch(shuffled, "default")

    assert second.reused is False
    assert second.batch_id != first.batch_id
    assert second.policy_version == 2
    assert second.summary.allow_with_warning == 3
    assert second.summary.deny == 0
    _assert_items_align_with_submission(second, shuffled)
    log.info(
        "版本变更：v1 批次 %s 不复用到 v2 批次 %s，按 v%s 逐条=%s",
        first.batch_id,
        second.batch_id,
        second.policy_version,
        [i.decision.action.value for i in second.items],
    )


def test_concurrent_reordered_batches_each_get_own_order(container, published_policy):
    """多个定时任务同时交同一批（顺序各不相同）：各自按自己的提交顺序对齐。"""
    base = [
        _named_resource("conc-allow"),
        _named_resource("conc-deny", image="nginx:latest"),
        _named_resource("conc-warn", with_limits=False),
        {"kind": "Pod"},  # 一条不合法
    ]
    n = 8
    rng = random.Random(20261004)
    orders = []
    while len(orders) < n:
        perm = list(base)
        rng.shuffle(perm)
        if perm not in orders:
            orders.append(perm)

    barrier = threading.Barrier(n)

    def worker(order):
        barrier.wait()
        return order, container.batch_service.admit_batch(order, "default")

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = [f.result() for f in as_completed([pool.submit(worker, o) for o in orders])]

    # 批次与判定记录全局唯一
    assert len({b.batch_id for _, b in results}) == 1
    assert len(container.batch_store.list_all()) == 1
    assert len(container.decision_store.list_all()) == 3  # 3 条合法资源各一条
    # 每个提交方拿到的逐条结果都按它自己的提交顺序排列
    for order, batch in results:
        assert batch.summary == results[0][1].summary
        _assert_items_align_with_submission(batch, order)
    log.info(
        "并发换序同批：%d 线程各自顺序 -> 唯一批次 %s 判定记录=%d 汇总=%s",
        n,
        results[0][1].batch_id,
        len(container.decision_store.list_all()),
        results[0][1].summary.rationale,
    )


def test_reordered_resubmit_over_http(client):
    """HTTP 端到端：换序重交后 items 按本次提交顺序返回，不合法条目位置正确。"""
    assert client.post("/api/policies", json={"document": make_policy_document()}).status_code == 200

    allow_res = _named_resource("http-allow")
    invalid_res = {"kind": "Pod"}
    deny_res = _named_resource("http-deny", image="nginx:latest")

    r1 = client.post(
        "/api/admit/batch",
        json={"policy_name": "default", "resources": [allow_res, invalid_res, deny_res]},
    )
    assert r1.status_code == 200
    body1 = r1.json()
    assert [i["status"] for i in body1["items"]] == ["decided", "invalid", "decided"]

    # 换序重交
    r2 = client.post(
        "/api/admit/batch",
        json={"policy_name": "default", "resources": [deny_res, allow_res, invalid_res]},
    )
    assert r2.status_code == 200
    body2 = r2.json()
    assert body2["reused"] is True
    assert body2["batch_id"] == body1["batch_id"]
    assert body2["summary"] == body1["summary"]
    # 逐条按本次提交顺序：deny / allow / invalid，index 从 0 顺排
    assert [i["index"] for i in body2["items"]] == [0, 1, 2]
    assert body2["items"][0]["decision"]["action"] == "deny"
    assert body2["items"][1]["decision"]["action"] == "allow"
    assert body2["items"][2]["status"] == "invalid"
    assert body2["items"][2]["error"]["error"] == "resource_validation_failed"
    # 每条结论仍属于对应资源本身
    assert body2["items"][0]["decision"]["resource_ref"].endswith("/http-deny")
    assert body2["items"][1]["decision"]["resource_ref"].endswith("/http-allow")
    log.info(
        "HTTP 换序重交：batch=%s 策略 v%s 逐条状态=%s 汇总=%s",
        body2["batch_id"],
        body2["policy"]["version"],
        [i["status"] for i in body2["items"]],
        body2["summary"]["rationale"],
    )
