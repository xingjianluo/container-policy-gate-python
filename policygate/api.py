"""FastAPI HTTP 接口：把领域错误映射为带 reason 码的结构化响应。"""
from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .exceptions import GateError
from .models import RejectReason
from .service import GateService

_POLICY_DIR = os.environ.get("POLICYGATE_POLICY_DIR", "data/policies")
_STATE_DIR = os.environ.get("POLICYGATE_STATE_DIR", "data/state")


def create_app(
    policy_dir: str | None = None,
    state_dir: str | None = None,
) -> FastAPI:
    app = FastAPI(title="container-policy-gate", version="0.1.0")
    service = GateService(
        policy_dir or _POLICY_DIR,
        state_dir or _STATE_DIR,
    )
    app.state.service = service

    @app.exception_handler(GateError)
    async def gate_error_handler(request: Request, exc: GateError) -> JSONResponse:
        # 409：重复/幂等冲突、非法状态流转；422：其余可区分的拒绝原因。
        status = (
            409
            if exc.reason
            in (
                RejectReason.DUPLICATE_SUBMISSION_CONFLICT,
                RejectReason.ILLEGAL_STATE_TRANSITION,
            )
            else 422
        )
        return JSONResponse(
            status_code=status,
            content={"error": True, "reason": exc.reason.value, "detail": exc.detail},
        )

    @app.get("/health")
    def health() -> dict:
        return {
            "status": "ok",
            "policy_versions": service.policy_store.all_versions(),
            "latest": service.policy_store.latest_version(),
        }

    @app.post("/admit")
    async def admit(request: Request) -> dict:
        body = await request.json()
        key = body.pop("idempotency_key", None) if isinstance(body, dict) else None
        policy_version = body.pop("policy_version", None) if isinstance(body, dict) else None
        return service.admit(body, idempotency_key=key, policy_version=policy_version)

    @app.get("/resources/{resource_uid:path}/history")
    def history(resource_uid: str) -> dict:
        return {"resource_uid": resource_uid, "records": service.history(resource_uid)}

    @app.get("/resources/{resource_uid:path}/replay")
    def replay(resource_uid: str, record_id: str | None = None) -> dict:
        return service.replay(resource_uid, record_id)

    @app.post("/exemptions")
    async def submit_exemption(request: Request) -> dict:
        body = await request.json()
        key = body.pop("idempotency_key", None) if isinstance(body, dict) else None
        return service.submit_exemption(body, idempotency_key=key)

    @app.post("/exemptions/{exemption_id}/transitions/{action}")
    def transition_exemption(exemption_id: str, action: str) -> dict:
        return service.transition_exemption(exemption_id, action)

    @app.post("/exemptions/check")
    async def check_exemption(request: Request) -> dict:
        return service.check_exemption(await request.json())

    return app


app = create_app()
