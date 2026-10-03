"""换序重交与重复提交的逐条位置对齐。

覆盖业务：
- 同一批资源内容不变、仅换序重交：逐条结果按【本次】提交顺序排列，
  与资源按位置一一对应；批次标识与汇总与首次一致，不产生新记录；
- 批次混入不合法条目时换序：不合法条目落回它本次的位置；
- 批内含完全相同的条目时换序/重复提交：位置对应关系与汇总都不乱；
- 多个定时任务并发交同一批（顺序各不相同）：各自响应按各自请求
  顺序对齐，批次记录唯一、判定记录不重复；
- 资源内容变更或策略版本变更 => 新的一批，不错误复用。
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from app.models import BATCH_ITEM_DECIDED, BATCH_ITEM_INVALID
from app.resource import fingerprint

from .conftest import make_policy_document
from .test_batch import _named_resource

log = logging.getLogger("test.batch_reorder")


def _fp_of_item(item) -> str:
    """条目内容指纹：decided 取判定的资源指纹，invalid 取条目指纹。"""
    if item.decision is not None:
        return item.decision.resource_fingerprint
    return item.item_fingerprint


def _assert_aligned(batch, resources) -> None:
    """断言逐条结果与本次提交的资源按位置一一对应。"""
    assert len(batch.items) == len(resources)
    for pos, (item, resource) in enumerate(zip(batch.items, resources)):
        assert item.index == pos
        assert _fp_of_item(item) == fingerprint(resource)


def test_reorder_resubmission_items_follow_request_order(container, published_policy):
    """换序重交：逐条结果按本次提交顺序排列，批次标识与汇总不变。"""
    resources = [_named_resource(f"ord-{i}") for i in range(5)]
    resources[1]["spec"]["image"] = "nginx:latest"      # deny
    resources[3]["spec"]["image"] = "redis:7.2"
    del resources[3]["spec"]["resources"]               # warn（缺 limits）

    first = container.batch_service.admit_batch(resources, "default")
    reordered = [resources[3], resources[0], resources[4], resources[1], resources[2]]
    second = container.batch_service.admit_batch(reordered, "default")

    # 仍算同一批：标识、汇总一致，不产生新的批次/判定记录
    assert second.reused is True
    assert second.batch_id == first.batch_id
    assert second.summary == first.summary
    assert len(container.batch_store.list_all()) == 1
    assert len(container.decision_store.list_all()) == 5

    # 逐条结果按本次提交顺序与资源一一对应（修复前这里会错位）
    _assert_aligned(second, reordered)
    # 每条结论内容本身与首次一致（同一资源同一判定）
    first_by_fp = {_fp_of_item(i): i for i in first.items}
    for item in second.items:
        assert item.decision.decision_id == first_by_fp[_fp_of_item(item)].decision.decision_id
    log.info(
        "换序重交：batch=%s 策略 v%s 顺序=%s 逐条已按本次提交对齐，汇总=%s",
        second.batch_id,
        second.policy_version,
        [i.resource_ref for i in second.items],
        second.summary.rationale,
    )


def test_reorder_with_invalid_item_lands_on_its_position(container, published_policy):
    """混入不合法条目时换序重交：不合法条目落回它本次的位置。"""
    invalid = {"kind": "Deployment"}  # 缺 apiVersion/metadata/spec
    resources = [
        _named_resource("mix-0"),
        invalid,
        _named_resource("mix-2", image="nginx:latest"),
    ]
    first = container.batch_service.admit_batch(resources, "default")
    assert first.items[1].status == BATCH_ITEM_INVALID

    reordered = [resources[2], resources[0], invalid]  # 不合法条目换到位置 2
    second = container.batch_service.admit_batch(reordered, "default")

    assert second.reused is True
    assert second.batch_id == first.batch_id
    assert second.summary == first.summary
    _assert_aligned(second, reordered)
    # 不合法条目落在本次的位置 2，其余位置都是 decided
    assert second.items[2].status == BATCH_ITEM_INVALID
    assert second.items[2].error["error"] == "resource_validation_failed"
    assert second.items[0].status == BATCH_ITEM_DECIDED
    assert second.items[1].status == BATCH_ITEM_DECIDED
    # 不合法条目不产生判定记录：总数不变
    assert len(container.decision_store.list_all()) == 2
    log.info(
        "不合法条目换序：位置 1 -> 2，状态=%s 原因=%s；批次=%s 汇总=%s",
        second.items[2].status,
        second.items[2].error["message"],
        second.batch_id,
        second.summary.rationale,
    )


def test_reorder_with_duplicate_items_in_batch(container, published_policy):
    """批内含完全相同的条目：换序/重复提交后位置对应与汇总都不乱。"""
    dup = _named_resource("dup")  # 同一份内容出现两次
    resources = [
        dup,
        _named_resource("uniq-1", image="nginx:latest"),
        dup,
        _named_resource("uniq-3"),
    ]
    first = container.batch_service.admit_batch(resources, "default")
    assert first.summary.total == 4
    # 相同内容只产生一条判定记录（2 个 dup + 2 个 uniq => 3 条）
    assert len(container.decision_store.list_all()) == 3

    reordered = [resources[3], resources[2], resources[1], resources[0]]
    second = container.batch_service.admit_batch(reordered, "default")

    assert second.reused is True
    assert second.batch_id == first.batch_id
    assert second.summary == first.summary
    _assert_aligned(second, reordered)
    # 位置 1 与位置 3 都是 dup 的结论（同一条判定记录）
    assert second.items[1].decision.decision_id == second.items[3].decision.decision_id
    assert len(container.batch_store.list_all()) == 1
    assert len(container.decision_store.list_all()) == 3
    log.info(
        "批内重复条目换序：位置=%s 共用判定=%s 汇总=%s",
        [i.index for i in second.items if i.resource_ref == second.items[1].resource_ref],
        second.items[1].decision.decision_id[:8],
        second.summary.rationale,
    )


def test_concurrent_reordered_batches_each_aligned_to_own_request(
    container, published_policy
):
    """多个定时任务同时交同一批（顺序各不相同）：各自对齐、记录唯一。"""
    base = [_named_resource("cron-0"), {"kind": "Deployment"}] + [
        _named_resource(f"cron-{i}") for i in range(1, 6)
    ]
    orders = [
        base,
        list(reversed(base)),
        [base[2], base[0], base[6], base[1], base[3], base[4], base[5]],
    ]
    n = len(orders)
    barrier = threading.Barrier(n)

    def worker(resources):
        barrier.wait()
        return container.batch_service.admit_batch(resources, "default")

    with ThreadPoolExecutor(max_workers=n) as pool:
        batches = list(pool.map(worker, orders))

    # 同一批：批次记录唯一、判定记录不重复
    assert len({b.batch_id for b in batches}) == 1
    assert len(container.batch_store.list_all()) == 1
    assert len(container.decision_store.list_all()) == 6  # 6 条合法资源各一条
    # 每个响应都按各自请求的提交顺序对齐，不合法条目位置各异也都对
    for batch, resources in zip(batches, orders):
        _assert_aligned(batch, resources)
        invalid_positions = [
            i for i, r in enumerate(resources) if not isinstance(r, dict) or "spec" not in r
        ]
        for pos in invalid_positions:
            assert batch.items[pos].status == BATCH_ITEM_INVALID
    log.info(
        "并发换序同批：%d 个定时任务 -> 唯一批次 %s，各响应均按各自提交顺序对齐",
        n,
        batches[0].batch_id,
    )


def test_content_change_makes_new_batch(container, published_policy):
    """资源内容确实改了 => 新的一批，不得复用旧批次。"""
    resources = [_named_resource(f"chg-{i}") for i in range(3)]
    first = container.batch_service.admit_batch(resources, "default")

    changed = [dict(r) for r in resources]
    changed[1] = _named_resource("chg-1", image="nginx:latest")  # 一条内容变更
    second = container.batch_service.admit_batch(changed, "default")

    assert second.reused is False
    assert second.batch_id != first.batch_id
    assert len(container.batch_store.list_all()) == 2
    _assert_aligned(second, changed)
    log.info(
        "内容变更：新批次 %s（旧 %s），策略 v%s",
        second.batch_id,
        first.batch_id,
        second.policy_version,
    )


def test_policy_version_change_makes_new_batch(container, published_policy):
    """策略版本换了 => 同一份资源清单也算新的一批。"""
    resources = [_named_resource(f"ver-{i}") for i in range(3)]
    first = container.batch_service.admit_batch(resources, "default")

    doc2 = make_policy_document(version=2)
    doc2["rules"][0]["on_violation"] = "warn"
    container.policy_store.publish(doc2)

    second = container.batch_service.admit_batch(resources, "default")
    assert second.reused is False
    assert second.batch_id != first.batch_id
    assert second.policy_version == 2
    assert len(container.batch_store.list_all()) == 2

    # v2 下换序重交：仍复用 v2 的批次，且按本次顺序对齐
    reordered = list(reversed(resources))
    third = container.batch_service.admit_batch(reordered, "default")
    assert third.reused is True
    assert third.batch_id == second.batch_id
    _assert_aligned(third, reordered)
    assert len(container.batch_store.list_all()) == 2
    log.info(
        "版本变更：v1 批次 %s 不复用到 v2（新批次 %s）；v2 内换序重交仍对齐",
        first.batch_id,
        second.batch_id,
    )


def test_http_reorder_resubmission_aligned(client):
    """HTTP 端到端：换序重交时响应逐条按本次提交顺序排列。"""
    assert client.post("/api/policies", json={"document": make_policy_document()}).status_code == 200

    resources = [
        _named_resource("http-0"),
        {"kind": "Pod"},  # 不合法
        _named_resource("http-2", image="nginx:latest"),
    ]
    r1 = client.post("/api/admit/batch", json={"resources": resources, "policy_name": "default"})
    assert r1.status_code == 200
    body1 = r1.json()

    reordered = [resources[2], resources[0], resources[1]]
    r2 = client.post(
        "/api/admit/batch", json={"resources": reordered, "policy_name": "default"}
    )
    body2 = r2.json()

    assert body2["reused"] is True
    assert body2["batch_id"] == body1["batch_id"]
    assert body2["summary"] == body1["summary"]
    items = body2["items"]
    assert [i["index"] for i in items] == [0, 1, 2]
    # 位置 0 是原来的 deny 资源，位置 1 是 allow，位置 2 是不合法条目
    assert items[0]["decision"]["action"] == "deny"
    assert items[0]["decision"]["resource_ref"].endswith("/http-2")
    assert items[1]["decision"]["action"] == "allow"
    assert items[2]["status"] == "invalid"
    assert items[2]["error"]["error"] == "resource_validation_failed"
    log.info(
        "HTTP 换序重交：batch=%s 策略 v%s 逐条位置=[deny, allow, invalid] 与本次提交一致",
        body2["batch_id"],
        body2["policy"]["version"],
    )
