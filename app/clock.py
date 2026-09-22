"""可注入的时钟。

业务代码一律通过时钟取“当前时间”，测试中可冻结/拨快时间，
从而确定性地验证豁免生效期、历史判定按发生时刻复现。
所有时间统一为带 tzinfo 的 UTC。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


def utcnow() -> datetime:
    """系统当前 UTC 时间（带 tzinfo）。"""
    return datetime.now(UTC)


def to_iso(dt: datetime) -> str:
    """统一的 ISO8601 UTC 字符串（Z 结尾）。"""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    """解析 ISO8601 字符串；无时区者按 UTC 处理。"""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


class Clock:
    """时钟接口。"""

    def now(self) -> datetime:
        """返回当前 UTC 时间（带 tzinfo）。"""
        raise NotImplementedError


class SystemClock(Clock):
    """系统真实时钟。"""

    def now(self) -> datetime:
        return utcnow()


class FixedClock(Clock):
    """固定时钟，始终返回同一时刻；可手动推进。"""

    def __init__(self, moment: datetime | None = None) -> None:
        if moment is None:
            moment = utcnow()
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        self._moment = moment.astimezone(UTC)

    def now(self) -> datetime:
        return self._moment

    def advance(self, **delta) -> None:
        """推进内部时刻（timedelta 关键字参数，如 seconds=... / days=...）。"""
        self._moment += timedelta(**delta)
