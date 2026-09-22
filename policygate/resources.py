"""资源清单解析：必填字段校验（缺失即拒绝，绝不静默放行）与资源指纹。"""
from __future__ import annotations

from .exceptions import ResourceValidationError
from .fingerprints import sha256_fingerprint
from .models import RejectReason, Resource

_REQUIRED_TOP = ("apiVersion", "kind", "metadata")


def parse_resource(data: object) -> Resource:
    """把外部提交的 dict 解析为 :class:`Resource`。

    必填字段：apiVersion、kind、metadata.name。
    namespace 缺省为 "default"；metadata.uid 缺省时按
    "kind/namespace/name" 合成稳定标识。
    """
    if not isinstance(data, dict):
        raise ResourceValidationError(
            RejectReason.RESOURCE_FIELD_MISSING,
            "资源清单必须是 JSON 对象",
        )
    missing = [k for k in _REQUIRED_TOP if k not in data]
    if missing:
        raise ResourceValidationError(
            RejectReason.RESOURCE_FIELD_MISSING,
            f"资源清单缺少必填字段: {', '.join(missing)}",
        )
    api_version = data["apiVersion"]
    if not isinstance(api_version, str) or not api_version:
        raise ResourceValidationError(
            RejectReason.RESOURCE_FIELD_MISSING,
            "apiVersion 必须是非空字符串",
        )
    kind = data["kind"]
    if not isinstance(kind, str) or not kind:
        raise ResourceValidationError(
            RejectReason.RESOURCE_FIELD_MISSING,
            "kind 必须是非空字符串",
        )
    metadata = data["metadata"]
    if not isinstance(metadata, dict):
        raise ResourceValidationError(
            RejectReason.RESOURCE_FIELD_MISSING,
            "metadata 必须是对象",
        )
    name = metadata.get("name")
    if not isinstance(name, str) or not name:
        raise ResourceValidationError(
            RejectReason.RESOURCE_FIELD_MISSING,
            "metadata.name 必须是非空字符串",
        )
    namespace = metadata.get("namespace", "default")
    if not isinstance(namespace, str) or not namespace:
        raise ResourceValidationError(
            RejectReason.RESOURCE_FIELD_MISSING,
            "metadata.namespace 若提供必须是非空字符串",
        )
    labels = metadata.get("labels", {})
    if not isinstance(labels, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in labels.items()
    ):
        raise ResourceValidationError(
            RejectReason.RESOURCE_FIELD_MISSING,
            "metadata.labels 必须是字符串到字符串的映射",
        )
    spec = data.get("spec", {})
    if not isinstance(spec, dict):
        raise ResourceValidationError(
            RejectReason.RESOURCE_FIELD_MISSING,
            "spec 若提供必须是对象",
        )
    uid = metadata.get("uid")
    if not isinstance(uid, str) or not uid:
        uid = f"{kind}/{namespace}/{name}"
    return Resource(
        uid=uid,
        api_version=api_version,
        kind=kind,
        namespace=namespace,
        name=name,
        spec=dict(spec),
        labels=dict(labels),
        raw=dict(data),
    )


def resource_fingerprint(resource: Resource) -> str:
    """资源内容指纹：覆盖提交清单的规范 JSON，不含派生 uid。"""
    return sha256_fingerprint(resource.raw)
