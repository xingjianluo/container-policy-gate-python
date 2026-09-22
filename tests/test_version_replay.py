"""版本可复现：策略变化后，历史判定仍按发生时的版本与指纹稳定复现。"""

from __future__ import annotations

import copy
import json
import logging

import pytest

from app.errors import PolicyVersionConflict
from app.models import Action, Severity

from .conftest import bad_resource

log = logging.getLogger("test.version_replay")


def test_history_not_overwritten_by_new_policy(container, published_policy):
    d1 = container.evaluator.admit(bad_resource(), "default", idempotency_key="h1")
    assert d1.action is Action.DENY
    v1_hit = next(h for h in d1.hits if h.rule_id == "image-fixed-tag")
    assert v1_hit.severity is Severity.HIGH
    log.info(
        "历史判定输入=%s 命中策略版本=v%s fp=%s 结论=%s",
        d1.resource_ref, d1.policy_version, d1.policy_fingerprint[:12], d1.action.value,
    )

    # 发布 v2：规则改严（critical）
    doc2 = copy.deepcopy(published_policy)
    doc2["version"] = 2
    doc2["rules"][0]["severity"] = "critical"
    container.policy_store.publish(doc2)

    # 同输入按最新策略判定 -> 新版本、新结论记录
    d2 = container.evaluator.admit(bad_resource(), "default", idempotency_key="h2")
    assert d2.policy_version == 2
    assert d2.decision_id != d1.decision_id
    assert d2.policy_fingerprint != d1.policy_fingerprint

    # 历史记录原封不动
    stored = container.evaluator.get_decision(d1.decision_id)
    assert stored.policy_version == 1
    assert stored.policy_fingerprint == d1.policy_fingerprint
    assert stored.action is Action.DENY


def test_replay_matches_historical_version(container, published_policy):
    d1 = container.evaluator.admit(bad_resource(), "default", idempotency_key="r1")

    doc2 = copy.deepcopy(published_policy)
    doc2["version"] = 2
    doc2["rules"][0]["severity"] = "critical"
    container.policy_store.publish(doc2)

    result = container.evaluator.replay(d1.decision_id)
    assert result["consistent"] is True
    assert result["policy_version"] == 1
    assert result["stored"]["action"] == "deny"
    replay_hit = next(
        h for h in result["recomputed"]["hits"] if h["rule_id"] == "image-fixed-tag"
    )
    assert replay_hit["severity"] == "high"  # 不是 v2 的 critical
    log.info(
        "复现成功 decision=%s 策略版本=v%s fp=%s 结论=%s",
        d1.decision_id[:8], result["policy_version"],
        result["policy_fingerprint"][:12], result["stored"]["action"],
    )


def test_replay_repeated_is_stable(container, published_policy):
    d = container.evaluator.admit(bad_resource(), "default", idempotency_key="r2")
    results = [container.evaluator.replay(d.decision_id) for _ in range(3)]
    assert all(r["consistent"] for r in results)
    fps = {r["policy_fingerprint"] for r in results}
    assert len(fps) == 1


def test_policy_versions_are_immutable(container, published_policy):
    """同版本号重发（即使内容不同）必须被拒绝。"""
    evil = copy.deepcopy(published_policy)
    evil["rules"][0]["severity"] = "low"  # 试图弱化已有版本
    with pytest.raises(PolicyVersionConflict) as exc:
        container.policy_store.publish(evil)
    assert exc.value.code == "policy_version_conflict"
    policy = container.policy_store.get("default", 1)
    assert policy.rules[0].severity is Severity.HIGH  # 原内容不变


def test_version_must_be_strictly_next(container, published_policy):
    jump = copy.deepcopy(published_policy)
    jump["version"] = 5  # 跳号
    with pytest.raises(PolicyVersionConflict) as exc:
        container.policy_store.publish(jump)
    assert exc.value.details["expected"] == 2


def test_persistence_files_survive_container_restart(tmp_path, clock):
    """落盘后重建容器，历史判定与策略指纹仍可复现。"""
    from app.service import Container

    data_dir = tmp_path / "data"
    c1 = Container.create(data_dir=data_dir, clock=clock)
    doc = {
        "name": "default",
        "version": 1,
        "rules": [
            {"id": "r1", "field": "spec.image", "operator": "present",
             "severity": "high", "on_violation": "deny"}
        ],
    }
    c1.policy_store.publish(doc)
    resource = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": "web", "namespace": "prod"}, "spec": {},
    }
    d = c1.evaluator.admit(resource, "default", idempotency_key="persist-1")

    c2 = Container.create(data_dir=data_dir, clock=clock)
    reloaded = c2.evaluator.get_decision(d.decision_id)
    assert reloaded is not None
    assert reloaded.policy_fingerprint == d.policy_fingerprint
    assert c2.evaluator.replay(d.decision_id)["consistent"] is True

    files = sorted(p.name for p in data_dir.glob("*.json"))
    log.info("落盘文件: %s", files)
    assert "policies.json" in files and "decisions.json" in files


def test_tampered_policy_fingerprint_is_rejected(tmp_path, clock):
    """直接篡改历史策略文件后，复现必须因指纹不符被拒绝。"""
    from app.service import Container

    data_dir = tmp_path / "data"
    c1 = Container.create(data_dir=data_dir, clock=clock)
    doc = {
        "name": "default", "version": 1,
        "rules": [
            {"id": "r1", "field": "spec.image", "operator": "present",
             "severity": "high", "on_violation": "deny"}
        ],
    }
    c1.policy_store.publish(doc)
    resource = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": "web", "namespace": "prod"}, "spec": {},
    }
    d = c1.evaluator.admit(resource, "default", idempotency_key="tamper-1")

    # 手工篡改磁盘上的策略：规则降级，并把指纹字段也改成与被篡改内容一致
    # （最强的篡改尝试）。复现时比对的是判定记录里固化的不可变指纹。
    policy_path = data_dir / "policies.json"
    on_disk = json.loads(policy_path.read_text(encoding="utf-8"))
    record = on_disk["policies"]["default"]["1"]
    record["rules"][0]["severity"] = "low"
    from app.resource import fingerprint as fp_of

    record["fingerprint"] = fp_of(
        {"raw_document": record["raw_document"], "rules": record["rules"]}
    )
    policy_path.write_text(json.dumps(on_disk), encoding="utf-8")

    c2 = Container.create(data_dir=data_dir, clock=clock)
    with pytest.raises(PolicyVersionConflict) as exc:
        c2.evaluator.replay(d.decision_id)
    assert "指纹" in exc.value.message
    assert exc.value.details["recorded_fingerprint"] != exc.value.details["current_fingerprint"]
