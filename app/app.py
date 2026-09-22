"""FastAPI 应用工厂：装配容器、注册路由、把业务错误映射为可区分 JSON。"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .api import router
from .errors import GateError
from .service import Container

logger = logging.getLogger("policy_gate")


def create_app(container: Container | None = None) -> FastAPI:
    """创建应用；container 为 None 时使用默认 ./data 目录。"""
    app = FastAPI(
        title="Container Policy Gate",
        version="0.1.0",
        description="本地容器与云原生资源配置合规准入服务",
    )
    app.state.container = container or Container.create(data_dir="data")
    app.include_router(router)

    @app.exception_handler(GateError)
    async def _gate_error_handler(request: Request, exc: GateError) -> JSONResponse:
        logger.warning("request rejected code=%s message=%s", exc.code, exc.message)
        return JSONResponse(status_code=exc.http_status, content=exc.to_dict())

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    return app
