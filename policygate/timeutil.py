"""时间工具：统一按 UTC 解析/比较 ISO-8601 字符串。

有效期字段（valid_from / valid_until）必须显式携带时区，避免"无时区本地时间"
在不同机器上比较结果不一致。
"""
from __future__ import annotations

from datetime import datetime, timezone


def parse_utc(value: object, field: str = "time") -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} 必须是非空 ISO-8601 字符串")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"{field} 不是合法 ISO-8601 时间: {value!r}") from exc
    if dt.tzinfo is None:
        raise ValueError(f"{field} 必须携带时区偏移（例如 Z 或 +08:00）: {value!r}")
    return dt.astimezone(timezone.utc)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def to_iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
