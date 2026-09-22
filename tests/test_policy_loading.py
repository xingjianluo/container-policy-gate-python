"""畸形策略文档 vs 不支持的规则语法：拒绝原因必须可区分；指纹必须稳定。"""
from __future__ import annotations

import copy
import json

import pytest

from policygate.exceptions import PolicyLoadError
from policygate.models import RejectReason
from policygate.policy_store import PolicyStore

from .conftest import POLICY_V1


def test_valid_policy_loads_with_stable_fingerprint(service):
    store = service.policy_store
    assert store.latest_version() == "v2"
    fp = store.fingerprint_of("v1")
    assert fp.startswith("sha256:")
    # 重新加载（模拟重启）指纹一致
    store2 = type(store)(store._dir)
    assert store2.fingerprint_of("v1") == fp
    # 内容变化 -> 指纹变化
    assert store.fingerprint_of("v2") != fp


def test_malformed_json_is_rejected_as_document_malformed(policy_factory):
    pdir, sdir = policy_factory("v1", "{not-json")
    with pytest.raises(PolicyLoadError) as exc:
        PolicyStore(pdir)
    assert exc.value.reason == RejectReason.POLICY_DOCUMENT_MALFORMED


def test_filename_version_mismatch_is_document_malformed(policy_factory):
    doc = copy.deepcopy(POLICY_V1)
    doc["version"] = "v9"
    pdir, _ = policy_factory("v1", doc)
    with pytest.raises(PolicyLoadError) as exc:
        PolicyStore(pdir)
    assert exc.value.reason == RejectReason.POLICY_DOCUMENT_MALFORMED


def test_bad_enum_is_document_malformed(policy_factory):
    doc = copy.deepcopy(POLICY_V1)
    doc["rules"][0]["severity"] = "weird"
    pdir, _ = policy_factory("v1", doc)
    with pytest.raises(PolicyLoadError) as exc:
        PolicyStore(pdir)
    assert exc.value.reason == RejectReason.POLICY_DOCUMENT_MALFORMED


def test_missing_required_rule_field_is_document_malformed(policy_factory):
    doc = copy.deepcopy(POLICY_V1)
    del doc["rules"][0]["severity"]
    pdir, _ = policy_factory("v1", doc)
    with pytest.raises(PolicyLoadError) as exc:
        PolicyStore(pdir)
    assert exc.value.reason == RejectReason.POLICY_DOCUMENT_MALFORMED


def test_unsupported_operator_is_rule_syntax_error(policy_factory):
    doc = copy.deepcopy(POLICY_V1)
    doc["rules"][0]["operator"] = "magic_contains"
    pdir, _ = policy_factory("v1", doc)
    with pytest.raises(PolicyLoadError) as exc:
        PolicyStore(pdir)
    assert exc.value.reason == RejectReason.RULE_SYNTAX_UNSUPPORTED
    assert "magic_contains" in exc.value.detail


def test_bad_field_path_is_rule_syntax_error(policy_factory):
    doc = copy.deepcopy(POLICY_V1)
    doc["rules"][0]["field_path"] = "spec.bad path"
    pdir, _ = policy_factory("v1", doc)
    with pytest.raises(PolicyLoadError) as exc:
        PolicyStore(pdir)
    assert exc.value.reason == RejectReason.RULE_SYNTAX_UNSUPPORTED


def test_operand_type_mismatch_is_rule_syntax_error(policy_factory):
    doc = copy.deepcopy(POLICY_V1)
    doc["rules"][0]["expected"] = "registry.internal"  # in 需要数组
    pdir, _ = policy_factory("v1", doc)
    with pytest.raises(PolicyLoadError) as exc:
        PolicyStore(pdir)
    assert exc.value.reason == RejectReason.RULE_SYNTAX_UNSUPPORTED


def test_invalid_regex_is_rule_syntax_error(policy_factory):
    doc = copy.deepcopy(POLICY_V1)
    doc["rules"][0]["operator"] = "regex"
    doc["rules"][0]["expected"] = "("
    pdir, _ = policy_factory("v1", doc)
    with pytest.raises(PolicyLoadError) as exc:
        PolicyStore(pdir)
    assert exc.value.reason == RejectReason.RULE_SYNTAX_UNSUPPORTED
