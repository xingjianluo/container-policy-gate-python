"""HTTP 路由：策略发布、准入判定、判定查询/复现、豁免管理。

请求体以原始 JSON 解析（不经 Pydantic 通用 422），
从而让业务层给出彼此可区分的拒绝原因。
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Request

from .errors import NotFound, PolicyDocumentError
from .models import Decision

router = APIRouter()


async def _json_body(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if not raw:
        raise PolicyDocumentError("请求体为空，需要 JSON 对象")
    try:
        body = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PolicyDocumentError(
            f"请求体不是合法 JSON: {exc}", details={"position": exc.pos}
        ) from exc
    if not isinstance(body, dict):
        raise PolicyDocumentError("请求体根节点必须是 JSON 对象")
    return body


def _container(request: Request):
    return request.app.state.container


# ---- 策略 ----


@router.post("/api/policies")
async def publish_policy(request: Request) -> dict[str, Any]:
    """发布新版本策略。body: {"document": {...}} 或直接是策略文档。"""
    body = await _json_body(request)
    document = body.get("document", body)
    policy = _container(request).policy_store.publish(document)
    return {
        "name": policy.name,
        "version": policy.version,
        "fingerprint": policy.fingerprint,
        "created_at": policy.created_at,
        "rule_count": len(policy.rules),
        "rules": [
            {
                "id": r.id,
                "severity": r.severity.value,
                "operator": r.operator,
                "field": r.field,
                "on_violation": r.on_violation,
            }
            for r in policy.rules
        ],
    }


@router.get("/api/policies/{name}")
async def get_policy(request: Request, name: str, version: int | None = None) -> dict[str, Any]:
    store = _container(request).policy_store
    policy = store.get(name, version) if version is not None else store.latest(name)
    if policy is None:
        raise NotFound(
            f"策略不存在: {name}" + (f"@v{version}" if version else ""),
        )
    return {
        "name": policy.name,
        "version": policy.version,
        "fingerprint": policy.fingerprint,
        "description": policy.description,
        "created_at": policy.created_at,
        "rules": [
            {
                "id": r.id,
                "description": r.description,
                "match": r.match,
                "field": r.field,
                "operator": r.operator,
                "value": r.value,
                "severity": r.severity.value,
                "on_violation": r.on_violation,
            }
            for r in policy.rules
        ],
        "versions": store.versions(name),
    }


# ---- 准入判定 ----


def _decision_to_response(decision: Decision, *, idempotent_hit: bool = False) -> dict[str, Any]:
    return {
        "decision_id": decision.decision_id,
        "idempotency_key": decision.idempotency_key,
        "resource_ref": decision.resource_ref,
        "resource_fingerprint": decision.resource_fingerprint,
        "policy": {
            "name": decision.policy_name,
            "version": decision.policy_version,
            "fingerprint": decision.policy_fingerprint,
        },
        "action": decision.action.value,
        "rationale": decision.rationale,
        "decided_at": decision.decided_at,
        "idempotent_hit": idempotent_hit,
        "hits": [
            {
                "rule_id": h.rule_id,
                "verdict": h.verdict.value,
                "severity": h.severity.value,
                "field": h.field,
                "operator": h.operator,
                "expected": h.expected,
                "actual": h.actual,
                "exempted": h.exempted,
                "exemption_id": h.exemption_id,
                "reason": h.reason,
            }
            for h in decision.hits
        ],
    }


@router.post("/api/admit")
async def admit(request: Request) -> dict[str, Any]:
    """提交资源清单做准入判定。

    body: {"resource": {...}, "policy_name": "...", "policy_version": 3,
           "idempotency_key": "..."}
    """
    body = await _json_body(request)
    resource = body.get("resource")
    if not isinstance(resource, dict):
        raise PolicyDocumentError("请求缺少 'resource' 对象")
    policy_name = body.get("policy_name", "default")
    policy_version = body.get("policy_version")
    idem_key = body.get("idempotency_key")

    container = _container(request)
    prior = (
        container.decision_store.get_by_idempotency_key(idem_key)
        if isinstance(idem_key, str)
        else None
    )
    decision = container.evaluator.admit(
        resource,
        policy_name,
        policy_version=policy_version if isinstance(policy_version, int) else None,
        idempotency_key=idem_key if isinstance(idem_key, str) else None,
    )
    return _decision_to_response(decision, idempotent_hit=prior is not None)


@router.get("/api/decisions/{decision_id}")
async def get_decision(request: Request, decision_id: str) -> dict[str, Any]:
    decision = _container(request).evaluator.get_decision(decision_id)
    if decision is None:
        raise NotFound(f"判定记录不存在: {decision_id}")
    return _decision_to_response(decision)


@router.post("/api/decisions/{decision_id}/replay")
async def replay_decision(request: Request, decision_id: str) -> dict[str, Any]:
    return _container(request).evaluator.replay(decision_id)


@router.get("/api/decisions")
async def list_decisions(request: Request) -> dict[str, Any]:
    decisions = _container(request).decision_store.list_all()
    return {"count": len(decisions), "decisions": [_decision_to_response(d) for d in decisions]}


# ---- 豁免 ----


@router.post("/api/exemptions")
async def request_exemption(request: Request) -> dict[str, Any]:
    body = await _json_body(request)
    svc = _container(request).exemption_service
    prior = None
    key = body.get("idempotency_key")
    if isinstance(key, str):
        data = svc.lookup_idempotency(key)
        if data is not None:
            prior = svc.get(data)
    exemption = svc.request(body)
    response = exemption.to_dict()
    response["idempotent_hit"] = prior is not None
    return response


@router.post("/api/exemptions/{exemption_id}/approve")
async def approve_exemption(request: Request, exemption_id: str) -> dict[str, Any]:
    return _container(request).exemption_service.approve(exemption_id).to_dict()


@router.post("/api/exemptions/{exemption_id}/reject")
async def reject_exemption(request: Request, exemption_id: str) -> dict[str, Any]:
    return _container(request).exemption_service.reject(exemption_id).to_dict()


@router.post("/api/exemptions/{exemption_id}/revoke")
async def revoke_exemption(request: Request, exemption_id: str) -> dict[str, Any]:
    return _container(request).exemption_service.revoke(exemption_id).to_dict()


@router.get("/api/exemptions/{exemption_id}")
async def get_exemption(request: Request, exemption_id: str) -> dict[str, Any]:
    return _container(request).exemption_service.get(exemption_id).to_dict()
