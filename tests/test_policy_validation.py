"""畸形策略 / 不支持的规则语法 / 资源字段缺失：拒绝原因必须彼此可区分。"""

from __future__ import annotations

import logging

import pytest

from app.errors import (
    PolicyDocumentError,
    ResourceValidationError,
    UnsupportedRuleError,
)
from app.policy_parser import parse_document

log = logging.getLogger("test.policy_validation")


def test_malformed_json_is_document_error():
    raw = '{"name": "default", "version": 1, broken}'
    with pytest.raises(PolicyDocumentError) as exc:
        parse_document(raw)
    assert exc.value.code == "policy_document_invalid"
    log.info("输入=%r -> code=%s", raw, exc.value.code)


def test_root_not_object_is_document_error():
    with pytest.raises(PolicyDocumentError) as exc:
        parse_document([1, 2, 3])
    assert exc.value.code == "policy_document_invalid"


@pytest.mark.parametrize(
    "doc",
    [
        {},  # 全缺
        {"name": "default"},  # 缺 version/rules
        {"name": "default", "version": 0, "rules": []},  # version 非法
        {"name": "default", "version": "1", "rules": []},  # version 类型错
        {"name": "", "version": 1, "rules": []},  # name 空
        {"name": "default", "version": 1, "rules": {}},  # rules 非数组
        {"name": "default", "version": 1, "rules": [{"id": "r"}]},  # 规则缺字段
        {
            "name": "default",
            "version": 1,
            "rules": [
                {"id": "r", "field": "spec.x", "operator": "eq", "value": 1},
                {"id": "r", "field": "spec.y", "operator": "eq", "value": 2},
            ],
        },  # 规则 id 重复
        {
            "name": "default",
            "version": 1,
            "rules": [
                {"id": "r", "field": "spec.x", "operator": "eq", "value": 1,
                 "severity": "catastrophic"}
            ],
        },  # severity 非法
        {
            "name": "default",
            "version": 1,
            "rules": [
                {"id": "r", "field": "spec.x", "operator": "eq", "value": 1,
                 "on_violation": "explode"}
            ],
        },  # on_violation 非法
        {
            "name": "default",
            "version": 1,
            "rules": [
                {"id": "r", "field": "spec.x", "operator": "eq", "value": 1,
                 "match": {"unknown_selector": "v"}}
            ],
        },  # match 未知键
    ],
)
def test_document_shape_errors_are_distinguishable(doc):
    with pytest.raises(PolicyDocumentError) as exc:
        parse_document(doc)
    assert exc.value.code == "policy_document_invalid"
    log.info("畸形文档输入=%s -> code=%s msg=%s", doc, exc.value.code, exc.value.message)


@pytest.mark.parametrize(
    "doc",
    [
        {
            "name": "default",
            "version": 1,
            "rules": [
                {"id": "r", "field": "spec.x", "operator": "some_weird_op", "value": 1}
            ],
        },  # 未知算子
        {
            "name": "default",
            "version": 1,
            "rules": [
                {"id": "r", "field": "spec.x", "operator": "in", "value": "not-a-list"}
            ],
        },  # in 右值不是数组
        {
            "name": "default",
            "version": 1,
            "rules": [
                {"id": "r", "field": "spec.x", "operator": "regex", "value": "("}
            ],
        },  # 非法正则
        {
            "name": "default",
            "version": 1,
            "rules": [
                {"id": "r", "field": "spec.x", "operator": "size_lte", "value": "3"}
            ],
        },  # size_lte 右值非整数
        {
            "name": "default",
            "version": 1,
            "rules": [
                {"id": "r", "field": "bad/path", "operator": "eq", "value": 1}
            ],
        },  # 字段路径语法不支持
    ],
)
def test_unsupported_rule_syntax_is_distinguishable(doc):
    with pytest.raises(UnsupportedRuleError) as exc:
        parse_document(doc)
    assert exc.value.code == "unsupported_rule_syntax"
    log.info("不受支持规则输入=%s -> code=%s msg=%s", doc, exc.value.code, exc.value.message)


def test_three_error_codes_are_distinct():
    """三类失败必须有三个不同 code。"""
    from app.policy_parser import parse_document as pd

    codes = set()
    with pytest.raises(PolicyDocumentError) as e1:
        pd('{"version": 1}')
    codes.add(e1.value.code)
    with pytest.raises(UnsupportedRuleError) as e2:
        pd(
            {
                "name": "p",
                "version": 1,
                "rules": [{"id": "r", "field": "x", "operator": "nope", "value": 1}],
            }
        )
    codes.add(e2.value.code)
    with pytest.raises(ResourceValidationError) as e3:
        from app.resource import validate_resource

        validate_resource({"kind": "Deployment"})
    codes.add(e3.value.code)
    assert codes == {
        "policy_document_invalid",
        "unsupported_rule_syntax",
        "resource_validation_failed",
    }
    log.info("三类拒绝码: %s", sorted(codes))


@pytest.mark.parametrize(
    "resource",
    [
        "not-an-object",
        [],
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {}},  # 缺 spec/name
        {"apiVersion": "apps/v1", "kind": "Deployment",
         "metadata": {"name": "x"}, "spec": []},  # spec 非对象
        {"apiVersion": 9, "kind": "Deployment",
         "metadata": {"name": "x"}, "spec": {}},  # apiVersion 类型错
        {"apiVersion": "apps/v1", "kind": "",
         "metadata": {"name": "x"}, "spec": {}},  # kind 空
        {"apiVersion": "apps/v1", "kind": "Deployment",
         "metadata": {"name": ""}, "spec": {}},  # name 空
        {"apiVersion": "apps/v1", "kind": "Deployment",
         "metadata": {"name": "x", "namespace": 7}, "spec": {}},  # namespace 类型错
    ],
)
def test_resource_missing_required_fields_rejected(resource):
    from app.resource import validate_resource

    with pytest.raises(ResourceValidationError) as exc:
        validate_resource(resource)
    assert exc.value.code == "resource_validation_failed"
    assert "missing" in exc.value.details or exc.value.details
    log.info("非法资源输入=%s -> code=%s", resource, exc.value.code)


def test_malformed_policy_does_not_become_allowing_policy(container):
    """畸形策略发布必须失败，且之后不会存在一个“零规则 -> 全放行”的版本。"""
    from fastapi.testclient import TestClient

    from app.app import create_app

    client = TestClient(create_app(container))
    r = client.post("/api/policies", json={"document": {"name": "default", "version": 1}})
    assert r.status_code == 422
    assert r.json()["error"] == "policy_document_invalid"
    r2 = client.get("/api/policies/default")
    assert r2.status_code == 404  # 没有任何版本被采纳
