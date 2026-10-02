"""批量准入与同内容重复上报收口。

覆盖业务：
- 批量提交：逐条结论 + 命中规则与依据 + 整批汇总，落在同一策略快照；
- 无幂等标识时同内容串行/并发重复上报自动收口，换内容或换策略版本算新提交；
- 批次混入不合法资源：单独标记该条，其余照常出结论；
- 批次执行期间策略版本变化：整批仍落在批次开始时的快照上；
- 整批重复/换序提交：复用首次批次结论，汇总一致；
- 较大批量（150 条）稳定跑完，不重不漏。
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.evaluator import Evaluator
from app.models import Action
from app.policy_store import PolicyStore

from .conftest import bad_resource, good_resource, make_policy_document

log = logging.getLogger("test.batch")


def _named(resource: dict, name: str) -> dict:
    r = {**resource, "metadata": {**resource["metadata"], "name": name}}
    return r


def _batch_of(n: int) -> list[dict]:
    """n 条互不相同的资源：偶数位合规、奇数位违规。"""
    return [
        _named(good_resource() if i % 2 == 0 else bad_resource(), f"web-{i}")
        for i in range(n)
    ]


# ---- 批量提交基本语义 ----


def test_batch_admit_per_item_and_summary(container, published_policy):
    resources = _batch_of(6)
    result = container.evaluator.admit_batch(resources, "default")

    assert len(result.items) == 6
    assert result.policy_version == 1
    assert len(result.policy_fingerprint) == 64
    # 每条都有结论、命中规则与判定依据
    for item in result.items:
        assert item.status == "decided"
        assert item.decision is not None
        assert item.decision.policy_version == 1
        assert item.decision.hits  # 命中规则与依据齐全
        assert all(h.reason for h in item.decision.hits)
    # 汇总：3 放行 + 3 拒绝，整批结论 deny
    assert result.summary["total"] == 6
    assert result.summary["allow"] == 3
    assert result.summary["deny"] == 3
    assert result.summary["invalid"] == 0
    assert result.summary["overall_action"] == "deny"
    log.info(
        "批量提交 6 条 -> 策略 v%s fp=%s 汇总=%s",
        result.policy_version,
        result.policy_fingerprint[:12],
        result.summary,
    )


def test_batch_summary_order_independent(container, published_policy):
    """同一批资源换个顺序提交，汇总结果一致（复用同一批次记录）。"""
    resources = _batch_of(8)
    first = container.evaluator.admit_batch(resources, "default")
    reordered = list(reversed(resources))
    second = container.evaluator.admit_batch(reordered, "default")

    assert second.batch_fingerprint == first.batch_fingerprint
    assert second.batch_id == first.batch_id
    assert second.idempotent_hit is True
    assert second.summary == first.summary
    # 换序后每条资源仍对回自己的结论
    for item in second.items:
        original = resources[len(resources) - 1 - item.index]
        assert item.decision.resource_ref.endswith(original["metadata"]["name"])
    log.info(
        "换序提交 -> 复用批次 %s 汇总一致: %s", second.batch_id[:8], second.summary
    )


# ---- 无幂等标识的重复上报收口 ----


def test_batch_repeat_submission_reuses_everything(container, published_policy):
    """整批重复提交：不产生重复判定记录，汇总与首次一致。"""
    resources = _batch_of(5)
    first = container.evaluator.admit_batch(resources, "default")
    records_after_first = len(container.decision_store.list_all())

    second = container.evaluator.admit_batch(resources, "default")
    assert second.idempotent_hit is True
    assert second.batch_id == first.batch_id
    assert second.summary == first.summary
    assert [i.decision.decision_id for i in second.items] == [
        i.decision.decision_id for i in first.items
    ]
    assert len(container.decision_store.list_all()) == records_after_first
    log.info(
        "整批重复提交 -> 复用批次 %s，判定记录数不变=%d",
        second.batch_id[:8],
        records_after_first,
    )


def test_batch_partial_prior_decisions_no_dup_no_missing(container, published_policy):
    """批次里有一部分此前已判过：不重复记录，也不漏掉任何一条。"""
    resources = _batch_of(4)
    prior = container.evaluator.admit(resources[0], "default")  # 单条先判过
    assert len(container.decision_store.list_all()) == 1

    result = container.evaluator.admit_batch(resources, "default")
    assert len(result.items) == 4
    # 已判过的那条复用旧结论，其余三条新建
    assert result.items[0].reused is True
    assert result.items[0].decision.decision_id == prior.decision_id
    assert all(not item.reused for item in result.items[1:])
    assert len(container.decision_store.list_all()) == 4  # 不重不漏
    log.info(
        "批次含已判资源 -> 复用 %s，新建 3 条，总记录=4", prior.decision_id[:8]
    )


def test_concurrent_duplicate_admit_without_key(container, published_policy):
    """无幂等标识、多线程同时交同一份资源：只产生一条判定记录。"""
    n = 16

    def worker():
        return container.evaluator.admit(bad_resource(), "default")

    with ThreadPoolExecutor(max_workers=n) as pool:
        decisions = [f.result() for f in as_completed([pool.submit(worker) for _ in range(n)])]

    assert len({d.decision_id for d in decisions}) == 1
    assert len(container.decision_store.list_all()) == 1
    assert all(d.action is Action.DENY for d in decisions)
    log.info("16 并发同内容无键提交 -> 唯一判定 %s", decisions[0].decision_id[:8])


def test_concurrent_duplicate_batch_without_key(container, published_policy):
    """无幂等标识、多线程同时交同一个批次：批次与判定记录都唯一。"""
    resources = _batch_of(10)
    n = 8

    def worker():
        return container.evaluator.admit_batch(resources, "default")

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = [f.result() for f in as_completed([pool.submit(worker) for _ in range(n)])]

    assert len({r.batch_id for r in results}) == 1
    assert len({r.summary["rationale"] for r in results}) == 1
    # 每条资源只有一条判定记录
    assert len(container.decision_store.list_all()) == 10
    for r in results:
        assert len(r.items) == 10
    log.info(
        "8 并发同批提交 -> 唯一批次 %s，判定记录=10",
        results[0].batch_id[:8],
    )


def test_changed_content_or_new_policy_version_is_new_submission(container, published_policy):
    """资源内容改动或策略版本升级：必须视为新提交，不得复用旧结论。"""
    d1 = container.evaluator.admit(bad_resource(), "default")

    changed = bad_resource()
    changed["metadata"]["labels"]["app"] = "web-v2"  # 内容改动
    d2 = container.evaluator.admit(changed, "default")
    assert d2.decision_id != d1.decision_id

    doc2 = make_policy_document(version=2)
    doc2["rules"][0]["severity"] = "critical"
    container.policy_store.publish(doc2)
    d3 = container.evaluator.admit(bad_resource(), "default")  # 同内容但策略已 v2
    assert d3.decision_id != d1.decision_id
    assert d3.policy_version == 2
    # 旧版本显式重提仍复用 v1 的结论
    d4 = container.evaluator.admit(bad_resource(), "default", policy_version=1)
    assert d4.decision_id == d1.decision_id
    log.info(
        "内容变更/策略升级 -> 新判定 %s/%s；显式 v1 复用 %s",
        d2.decision_id[:8],
        d3.decision_id[:8],
        d4.decision_id[:8],
    )


# ---- 批次混入不合法资源 ----


def test_batch_with_invalid_resource_marks_only_that_item(container, published_policy):
    resources = _batch_of(3)
    resources.insert(1, {"kind": "Pod"})  # 缺 apiVersion/metadata/spec

    result = container.evaluator.admit_batch(resources, "default")
    assert len(result.items) == 4

    invalid = result.items[1]
    assert invalid.status == "invalid"
    assert invalid.decision is None
    assert invalid.error["error"] == "resource_validation_failed"
    assert "missing" in invalid.error["details"]

    for item in (result.items[0], result.items[2], result.items[3]):
        assert item.status == "decided"  # 其余照常出结论
    # 不合法条目计入汇总且拉低整批结论，绝不静默放行
    assert result.summary["invalid"] == 1
    assert result.summary["overall_action"] == "deny"
    # 不合法资源不产生判定记录
    assert len(container.decision_store.list_all()) == 3

    # 重复提交同一批：不合法标记也原样复用
    again = container.evaluator.admit_batch(resources, "default")
    assert again.idempotent_hit is True
    assert again.items[1].status == "invalid"
    assert again.summary == result.summary
    log.info(
        "批次混入不合法资源 -> 单独标记 index=1 (%s)，其余 3 条正常判定",
        invalid.error["message"],
    )


# ---- 批次执行期间策略版本变化 ----


class _MidBatchPublishStore(PolicyStore):
    """测试专用：批次首次取快照后立刻发布新版本，模拟执行中途的策略变更。"""

    def __init__(self, *args, trigger_doc: dict, **kwargs):
        super().__init__(*args, **kwargs)
        self._trigger_doc = trigger_doc
        self._fired = False

    def latest(self, name):
        policy = super().latest(name)
        if policy is not None and not self._fired:
            self._fired = True
            self.publish(self._trigger_doc)  # 快照已取走，此后 latest 应为 v2
        return policy


def test_batch_pins_single_policy_snapshot(container, published_policy):
    doc2 = make_policy_document(version=2)
    doc2["rules"][0]["severity"] = "critical"
    store = _MidBatchPublishStore(
        container.policy_json_store, container.clock, trigger_doc=doc2
    )
    container.evaluator = Evaluator(
        store, container.decision_store, container.exemption_service, container.clock
    )

    resources = _batch_of(20)
    result = container.evaluator.admit_batch(resources, "default")

    # 整批落在同一快照 v1 上，尽管执行期间 v2 已发布
    assert result.policy_version == 1
    assert all(item.decision.policy_version == 1 for item in result.items)
    assert all(
        item.decision.policy_fingerprint == result.policy_fingerprint
        for item in result.items
    )
    # 每条记录之后单独复现仍稳定一致（按 v1 重算）
    for item in result.items:
        replay = container.evaluator.replay(item.decision.decision_id)
        assert replay["consistent"] is True
        assert replay["policy_version"] == 1

    # 下一批按最新版 v2 判定
    follow_up = container.evaluator.admit_batch(_batch_of(2), "default")
    assert follow_up.policy_version == 2
    log.info(
        "批次执行中发布 v2 -> 本批 20 条全部按 v1(fp=%s) 判定且可复现，下一批按 v2",
        result.policy_fingerprint[:12],
    )


# ---- 较大批量 ----


def test_large_batch_stable_and_complete(container, published_policy):
    resources = _batch_of(150)
    result = container.evaluator.admit_batch(resources, "default")

    assert len(result.items) == 150
    assert result.summary["total"] == 150
    assert result.summary["allow"] == 75
    assert result.summary["deny"] == 75
    # 不重不漏：150 条资源各一条判定记录，decision_id 唯一
    ids = {item.decision.decision_id for item in result.items}
    assert len(ids) == 150
    assert len(container.decision_store.list_all()) == 150
    # 抽查复现
    for item in (result.items[0], result.items[75], result.items[149]):
        assert container.evaluator.replay(item.decision.decision_id)["consistent"]
    log.info(
        "150 条大批量 -> 汇总=%s 批次=%s", result.summary, result.batch_id[:8]
    )


# ---- HTTP 端到端 ----


def test_batch_api_endpoint(client, published_policy):
    resources = _batch_of(4)
    resources.append({"kind": "Pod"})  # 混入一条不合法
    r = client.post(
        "/api/admit/batch", json={"resources": resources, "policy_name": "default"}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["policy"]["version"] == 1
    assert body["summary"]["total"] == 5
    assert body["summary"]["invalid"] == 1
    assert len(body["items"]) == 5
    assert body["items"][4]["status"] == "invalid"
    assert body["idempotent_hit"] is False

    again = client.post(
        "/api/admit/batch", json={"resources": resources, "policy_name": "default"}
    ).json()
    assert again["idempotent_hit"] is True
    assert again["batch_id"] == body["batch_id"]
    assert again["summary"] == body["summary"]
    log.info(
        "HTTP 批量提交 -> 批次 %s 策略 v%s 汇总=%s",
        body["batch_id"][:8],
        body["policy"]["version"],
        body["summary"],
    )


def test_single_admit_api_content_dedup_flag(client, published_policy):
    """HTTP 单条提交不带幂等键：同内容重复提交返回复用标记。"""
    payload = {"resource": bad_resource(), "policy_name": "default"}
    first = client.post("/api/admit", json=payload).json()
    assert first["idempotent_hit"] is False
    second = client.post("/api/admit", json=payload).json()
    assert second["decision_id"] == first["decision_id"]
    assert second["idempotent_hit"] is True
    log.info(
        "HTTP 无键重复提交 -> 复用判定 %s idempotent_hit=true",
        second["decision_id"][:8],
    )
