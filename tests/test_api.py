"""HTTP 端到端：错误码可区分、幂等标记、豁免流程、复现接口。"""

from __future__ import annotations

import logging
from datetime import timedelta

from .conftest import bad_resource, good_resource, make_policy_document

log = logging.getLogger("test.api")


def _publish(client, doc=None):
    return client.post("/api/policies", json={"document": doc or make_policy_document()})


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_publish_and_get_policy(client):
    r = _publish(client)
    assert r.status_code == 200
    body = r.json()
    assert body["version"] == 1
    assert len(body["fingerprint"]) == 64
    assert body["rule_count"] == 2

    r2 = client.get("/api/policies/default")
    assert r2.status_code == 200
    assert r2.json()["fingerprint"] == body["fingerprint"]


def test_publish_version_conflict(client):
    assert _publish(client).status_code == 200
    r = _publish(client)  # 仍是 version=1
    assert r.status_code == 409
    assert r.json()["error"] == "policy_version_conflict"


def test_publish_malformed_policy_distinguishable_error(client):
    r1 = client.post("/api/policies", json={"document": {"name": "x", "version": 1}})
    assert r1.status_code == 422
    assert r1.json()["error"] == "policy_document_invalid"

    doc = make_policy_document()
    doc["rules"][0]["operator"] = "bogus"
    r2 = client.post("/api/policies", json={"document": doc})
    assert r2.status_code == 422
    assert r2.json()["error"] == "unsupported_rule_syntax"
    assert r1.json()["error"] != r2.json()["error"]


def test_admit_denied_and_allowed(client):
    _publish(client)
    r = client.post(
        "/api/admit",
        json={"resource": bad_resource(), "policy_name": "default", "idempotency_key": "a1"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "deny"
    assert body["policy"]["version"] == 1
    assert body["idempotent_hit"] is False
    assert len(body["hits"]) == 2
    log.info("API 判定输入=%s 策略版本=v%s fp=%s 依据=%s",
             body["resource_ref"], body["policy"]["version"],
             body["policy"]["fingerprint"][:12], body["rationale"])

    r_good = client.post("/api/admit", json={"resource": good_resource()})
    assert r_good.json()["action"] == "allow"


def test_admit_missing_fields_distinguishable(client):
    _publish(client)
    r = client.post("/api/admit", json={"resource": {"kind": "Pod"}})
    assert r.status_code == 422
    assert r.json()["error"] == "resource_validation_failed"
    assert "missing" in r.json()["details"]


def test_admit_idempotent_replay_flag(client):
    _publish(client)
    payload = {"resource": bad_resource(), "idempotency_key": "same"}
    first = client.post("/api/admit", json=payload).json()
    second = client.post("/api/admit", json=payload).json()
    assert first["decision_id"] == second["decision_id"]
    assert second["idempotent_hit"] is True


def test_get_decision_404(client):
    r = client.get("/api/decisions/nope")
    assert r.status_code == 404
    assert r.json()["error"] == "not_found"


def test_replay_endpoint(client):
    _publish(client)
    d = client.post(
        "/api/admit", json={"resource": bad_resource(), "idempotency_key": "rep"}
    ).json()
    # 发布新版本后，历史复现仍按 v1
    doc2 = make_policy_document(version=2)
    doc2["rules"][0]["severity"] = "critical"
    assert client.post("/api/policies", json={"document": doc2}).status_code == 200

    r = client.post(f"/api/decisions/{d['decision_id']}/replay")
    assert r.status_code == 200
    body = r.json()
    assert body["consistent"] is True
    assert body["policy_version"] == 1
    assert body["stored"]["action"] == "deny"


def test_full_exemption_flow_over_http(client):
    _publish(client)
    # 容器时钟从 app.state 取，构造有效期
    container = client.app.state.container
    now_dt = container.clock.now()
    payload = {
        "scope": {"kind": "Deployment", "namespace": "prod", "name": "web"},
        "rule_ids": ["image-fixed-tag"],
        "valid_from": (now_dt - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "valid_until": (now_dt + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "reason": "maintenance",
        "idempotency_key": "http-ex",
    }
    r = client.post("/api/exemptions", json=payload)
    assert r.status_code == 200
    ex = r.json()
    assert ex["status"] == "requested"

    # 重复提交
    r2 = client.post("/api/exemptions", json=payload)
    assert r2.json()["exemption_id"] == ex["exemption_id"]
    assert r2.json()["idempotent_hit"] is True

    # 批准前仍拒绝
    denied = client.post(
        "/api/admit", json={"resource": bad_resource(), "idempotency_key": "before"}
    ).json()
    assert denied["action"] == "deny"

    ra = client.post(f"/api/exemptions/{ex['exemption_id']}/approve")
    assert ra.status_code == 200 and ra.json()["status"] == "approved"

    warned = client.post(
        "/api/admit", json={"resource": bad_resource(), "idempotency_key": "after"}
    ).json()
    assert warned["action"] == "allow_with_warning"
    hit = next(h for h in warned["hits"] if h["rule_id"] == "image-fixed-tag")
    assert hit["exempted"] and hit["exemption_id"] == ex["exemption_id"]

    # 撤销后再次拒绝
    assert client.post(f"/api/exemptions/{ex['exemption_id']}/revoke").status_code == 200
    denied_again = client.post(
        "/api/admit", json={"resource": bad_resource(), "idempotency_key": "revoked"}
    ).json()
    assert denied_again["action"] == "deny"


def test_illegal_transition_http_status(client):
    container = client.app.state.container
    now_dt = container.clock.now()
    ex = container.exemption_service.request(
        {
            "scope": {},
            "rule_ids": [],
            "valid_from": (now_dt - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            "valid_until": (now_dt + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            "reason": "x",
        }
    )
    r = client.post(f"/api/exemptions/{ex.exemption_id}/revoke")
    assert r.status_code == 409
    assert r.json()["error"] == "illegal_state_transition"
