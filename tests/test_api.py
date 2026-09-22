"""HTTP 层：错误原因码透传、状态码映射、幂等回放。"""
from __future__ import annotations

from fastapi.testclient import TestClient

from policygate.api import create_app


def _client(tmp_path):
    return TestClient(create_app(str(tmp_path / "policies"), str(tmp_path / "state")))


def _bootstrap(tmp_path):
    import json

    (tmp_path / "policies").mkdir()
    (tmp_path / "state").mkdir()
    doc = {
        "version": "v1", "created_at": "2026-09-01T00:00:00Z",
        "rules": [
            {"id": "R1", "description": "白名单", "match_kinds": ["Pod"],
             "field_path": "spec.image_repository", "operator": "in",
             "expected": ["registry.internal"],
             "severity": "critical", "on_violation": "reject"},
        ],
    }
    (tmp_path / "policies" / "policy-v1.json").write_text(
        json.dumps(doc), encoding="utf-8")


def test_health(tmp_path):
    _bootstrap(tmp_path)
    client = _client(tmp_path)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["latest"] == "v1"


def test_admit_allow_and_deny(tmp_path):
    _bootstrap(tmp_path)
    client = _client(tmp_path)
    good = {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "ok", "namespace": "app"},
            "spec": {"image_repository": "registry.internal"}}
    r1 = client.post("/admit", json={"idempotency_key": "k1", **good})
    assert r1.status_code == 200 and r1.json()["result"]["action"] == "allow"
    bad = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": "bad", "namespace": "app"},
           "spec": {"image_repository": "docker.io/x"}}
    r2 = client.post("/admit", json={"idempotency_key": "k2", **bad})
    body = r2.json()
    assert body["result"]["decision"] == "reject"
    assert body["result"]["findings"][0]["rule_id"] == "R1"


def test_missing_field_returns_distinguishable_reason(tmp_path):
    _bootstrap(tmp_path)
    client = _client(tmp_path)
    resp = client.post("/admit", json={"apiVersion": "v1"})
    assert resp.status_code == 422
    assert resp.json()["reason"] == "resource_field_missing"


def test_idempotent_replay_endpoint(tmp_path):
    _bootstrap(tmp_path)
    client = _client(tmp_path)
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": "ok", "namespace": "app"},
           "spec": {"image_repository": "registry.internal"}}
    client.post("/admit", json={"idempotency_key": "k", **pod})
    replay = client.get("/resources/Pod/app/ok/replay")
    assert replay.status_code == 200
    assert replay.json()["result"]["replay"] is True


def test_illegal_transition_returns_409(tmp_path):
    _bootstrap(tmp_path)
    client = _client(tmp_path)
    payload = {"id": "E1", "rule_ids": ["R1"], "kinds": ["Pod"], "namespaces": ["app"],
               "valid_from": "2026-09-01T00:00:00Z",
               "valid_until": "2026-12-31T00:00:00Z", "reason": "r"}
    client.post("/exemptions", json=payload)
    resp = client.post("/exemptions/E1/transitions/revoke")  # pending -> revoke 非法
    assert resp.status_code == 409
    assert resp.json()["reason"] == "illegal_state_transition"
