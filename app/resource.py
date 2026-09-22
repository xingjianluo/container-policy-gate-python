"""资源清单校验、字段访问与选择器匹配。

必填字段缺失 / 类型不合法时抛 ResourceValidationError，
与策略文档错误（PolicyDocumentError）、规则语法错误（UnsupportedRuleError）
使用不同 error code，绝不静默放行。
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from .errors import ResourceValidationError
from .models import REQUIRED_RESOURCE_FIELDS

_MISSING = object()


def validate_resource(resource: Any) -> None:
    """校验资源清单必填字段。

    要求顶层为对象，且包含：apiVersion / kind / metadata / spec。
    metadata 必须为对象且含非空 name；namespace 可省略（集群级资源）。
    """
    if not isinstance(resource, dict):
        raise ResourceValidationError(
            "资源清单必须是一个 JSON 对象", details={"actual_type": type(resource).__name__}
        )

    missing: list[str] = []
    for field_name in REQUIRED_RESOURCE_FIELDS:
        if field_name not in resource or resource[field_name] is None:
            missing.append(field_name)
    if missing:
        raise ResourceValidationError(
            f"资源必填字段缺失: {', '.join(missing)}",
            details={"missing": missing, "required": list(REQUIRED_RESOURCE_FIELDS)},
        )

    kind = resource.get("kind")
    if not isinstance(kind, str) or not kind.strip():
        raise ResourceValidationError(
            "字段 'kind' 必须是非空字符串", details={"actual": kind}
        )
    api_version = resource.get("apiVersion")
    if not isinstance(api_version, str) or not api_version.strip():
        raise ResourceValidationError(
            "字段 'apiVersion' 必须是非空字符串", details={"actual": api_version}
        )

    metadata = resource.get("metadata")
    if not isinstance(metadata, dict):
        raise ResourceValidationError(
            "字段 'metadata' 必须是对象", details={"actual_type": type(metadata).__name__}
        )
    name = metadata.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ResourceValidationError(
            "字段 'metadata.name' 必须是非空字符串", details={"actual": name}
        )
    namespace = metadata.get("namespace")
    if namespace is not None and (not isinstance(namespace, str) or not namespace.strip()):
        raise ResourceValidationError(
            "字段 'metadata.namespace' 若提供必须是非空字符串",
            details={"actual": namespace},
        )

    if not isinstance(resource.get("spec"), dict):
        raise ResourceValidationError(
            "字段 'spec' 必须是对象",
            {"actual_type": type(resource.get("spec")).__name__},
        )


def get_field(resource: dict[str, Any], path: str) -> tuple[bool, Any]:
    """按点分路径读取字段，返回 (是否存在, 值)。

    - 支持 a.b.c 与数字下标（如 containers.0.image）；
    - 任一层类型不符、键不存在或下标越界 => (False, None)；
    - 空路径视为指向资源根对象。
    """
    if not isinstance(path, str) or not path.strip():
        return True, resource
    current: Any = resource
    for part in path.strip().split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            if 0 <= index < len(current):
                current = current[index]
            else:
                return False, None
        else:
            return False, None
    return True, current


def get_field_value(resource: dict[str, Any], path: str) -> Any:
    """读取字段值；不存在返回哨兵 MISSING（供 present/absent 精确区分）。"""
    exists, value = get_field(resource, path)
    return value if exists else _MISSING


def is_missing(value: Any) -> bool:
    return value is _MISSING


def resource_ref(resource: dict[str, Any]) -> str:
    """返回资源可读引用 kind/namespace/name。"""
    kind = resource.get("kind", "?")
    metadata = resource.get("metadata") if isinstance(resource.get("metadata"), dict) else {}
    namespace = metadata.get("namespace") or "_cluster"
    name = metadata.get("name", "?")
    return f"{kind}/{namespace}/{name}"


def canonical_json(data: Any) -> str:
    """规范化 JSON：键排序、无空白，用于稳定指纹。"""
    return json.dumps(
        data, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
    )


def fingerprint(data: Any) -> str:
    """对任意可 JSON 化数据计算 sha256 指纹。"""
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


def resource_fingerprint(resource: dict[str, Any]) -> str:
    """资源清单内容指纹 sha256。"""
    return fingerprint(resource)


def snapshot(resource: dict[str, Any]) -> dict[str, Any]:
    """资源深拷贝快照，判定记录保存它以保证历史可复现。"""
    return copy.deepcopy(resource)


def resource_matches(resource: dict[str, Any], selector: dict[str, Any]) -> bool:
    """资源是否被 match 选择器命中。

    支持键：kind / apiVersion / namespace / name / labels（标签子集匹配）。
    空选择器匹配一切；任一约束不满足即不匹配。
    """
    if not selector:
        return True

    metadata = resource.get("metadata") if isinstance(resource.get("metadata"), dict) else {}
    labels = metadata.get("labels") if isinstance(metadata.get("labels"), dict) else {}

    if "kind" in selector and resource.get("kind") != selector["kind"]:
        return False
    if "apiVersion" in selector and resource.get("apiVersion") != selector["apiVersion"]:
        return False
    if "name" in selector and metadata.get("name") != selector["name"]:
        return False
    if "namespace" in selector and metadata.get("namespace") != selector["namespace"]:
        return False

    required_labels = selector.get("labels")
    if required_labels is not None:
        if not isinstance(required_labels, dict):
            return False
        for key, value in required_labels.items():
            if labels.get(key) != value:
                return False
    return True
