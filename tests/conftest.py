"""共享测试夹具：构造两套策略目录（正常 v1/v2 + 可注入畸形策略）与临时状态目录。"""
from __future__ import annotations

import json
import os

import pytest

from policygate.service import GateService

POLICY_V1 = {
    "version": "v1",
    "created_at": "2026-09-01T00:00:00Z",
    "rules": [
        {"id": "R-IMAGE-REGISTRY", "description": "镜像仓库白名单",
         "match_kinds": ["Pod", "Deployment"], "field_path": "spec.image_repository",
         "operator": "in", "expected": ["registry.internal", "gcr.io"],
         "severity": "critical", "on_violation": "reject"},
        {"id": "R-CPU-LIMIT", "description": "必须声明 CPU 上限",
         "match_kinds": ["Pod"], "field_path": "spec.cpu_limit",
         "operator": "exists", "severity": "medium", "on_violation": "warn"},
        {"id": "R-NO-PRIVILEGED", "description": "禁止特权容器",
         "match_kinds": ["Pod"], "field_path": "spec.privileged",
         "operator": "not_equals", "expected": True,
         "severity": "high", "on_violation": "reject"},
    ],
}

POLICY_V2 = {
    "version": "v2",
    "created_at": "2026-09-20T00:00:00Z",
    "rules": [
        dict(POLICY_V1["rules"][0], expected=["registry.internal"]),
        POLICY_V1["rules"][1],
        POLICY_V1["rules"][2],
        {"id": "R-REPLICAS-MIN", "description": "副本数至少 2",
         "match_kinds": ["Deployment"], "field_path": "spec.replicas",
         "operator": "greater_than", "expected": 1,
         "severity": "medium", "on_violation": "warn"},
    ],
}


@pytest.fixture
def service(tmp_path):
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    for doc in (POLICY_V1, POLICY_V2):
        (policy_dir / f"policy-{doc['version']}.json").write_text(
            json.dumps(doc, ensure_ascii=False), encoding="utf-8"
        )
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    return GateService(str(policy_dir), str(state_dir))


@pytest.fixture
def policy_factory(tmp_path):
    """返回写策略文件的函数，便于构造畸形/不支持语法的策略。"""
    policy_dir = tmp_path / "policies_bad"
    policy_dir.mkdir()
    state_dir = tmp_path / "state_bad"
    state_dir.mkdir()

    def _write(version: str, content: str | dict):
        path = policy_dir / f"policy-{version}.json"
        if isinstance(content, str):
            path.write_text(content, encoding="utf-8")
        else:
            path.write_text(json.dumps(content, ensure_ascii=False), encoding="utf-8")
        return str(policy_dir), str(state_dir)

    return _write
