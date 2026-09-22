"""内容指纹：策略文档与资源清单的稳定哈希。

要求"策略内容发生变化后历史判定仍按当时指纹复现"，因此指纹必须：
- 与键顺序无关（sort_keys）
- 与空白/分隔写法无关（紧凑分隔符）
- 纯 stdlib、跨进程字节一致（UTF-8、ensure_ascii=False 但哈希十六进制不受显示影响）
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(obj: Any) -> str:
    """以键排序、无多余空白的方式序列化为规范 JSON 字符串。

    只接受 JSON 原生类型（dict/list/str/int/float/bool/None）；
    Enum 取其 value，其余类型直接抛错，避免隐式 str() 导致指纹漂移。
    """
    from enum import Enum

    def _normalize(value: Any) -> Any:
        if isinstance(value, Enum):
            return value.value
        if isinstance(value, dict):
            return {str(k): _normalize(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [_normalize(v) for v in value]
        if value is None or isinstance(value, (str, bool, int, float)):
            return value
        raise TypeError(f"无法纳入内容指纹的类型: {type(value).__name__}")

    return json.dumps(
        _normalize(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def sha256_fingerprint(obj: Any) -> str:
    """返回规范 JSON 的 SHA-256 十六进制摘要（64 位小写）。"""
    digest = hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"
