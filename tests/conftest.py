"""pytest 公共夹具：临时数据目录、冻结时钟、HTTP 客户端与示例策略。"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.app import create_app
from app.clock import FixedClock
from app.service import Container

# 让测试日志（含输入、策略版本与判定依据）在 -s 时直接可见
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s | %(message)s",
)

FROZEN = datetime(2026, 9, 23, 10, 0, 0, tzinfo=UTC)


def make_policy_document(*, version: int = 1, name: str = "default") -> dict:
    """标准示例策略：镜像必须打固定 tag(deny/high) + 必须设置 limits(warn/medium)。"""
    return {
        "name": name,
        "version": version,
        "description": "测试基线策略",
        "rules": [
            {
                "id": "image-fixed-tag",
                "description": "镜像不得使用 latest",
                "match": {"kind": "Deployment"},
                "field": "spec.image",
                "operator": "regex",
                "value": r":(?!latest$)[A-Za-z0-9._-]+$",
                "severity": "high",
                "on_violation": "deny",
            },
            {
                "id": "resources-limits-present",
                "description": "必须声明资源上限",
                "match": {"kind": "Deployment"},
                "field": "spec.resources.limits",
                "operator": "present",
                "severity": "medium",
                "on_violation": "warn",
            },
        ],
    }


def good_resource() -> dict:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "web", "namespace": "prod", "labels": {"app": "web"}},
        "spec": {"image": "nginx:1.27.0", "resources": {"limits": {"cpu": "1", "memory": "1Gi"}}},
    }


def bad_resource() -> dict:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "web", "namespace": "prod", "labels": {"app": "web"}},
        "spec": {"image": "nginx:latest"},
    }


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(FROZEN)


@pytest.fixture
def container(tmp_path, clock) -> Container:
    return Container.create(data_dir=tmp_path / "data", clock=clock)


@pytest.fixture
def client(container) -> TestClient:
    app = create_app(container)
    return TestClient(app)


@pytest.fixture
def published_policy(container) -> dict:
    doc = make_policy_document(version=1)
    container.policy_store.publish(doc)
    return doc
