"""豁免管理。

核心规则：
- 豁免带生效范围（rule_ids / kinds / namespaces / resource_uids，None 或 ["*"] 表示该维度不限）
  与有效期（[valid_from, valid_until]，闭区间，必须带时区）；
- 只有 status=active 且在有效期内、范围命中的豁免才生效；
  超范围 / 过期 / 未激活一律不得被采纳，且在 API 层给出可区分的拒绝原因；
- 状态机：pending -> active | rejected；active -> revoked；其余流转一律拒绝；
- 同一 idempotency_key 的重复提交返回既有对象，不产生重复记录；
- 文件级锁 + 读改写原子替换（tmp + os.replace）保证并发提交最终状态唯一。
"""
from __future__ import annotations

import contextlib
import dataclasses
import fcntl
import json
import os
import tempfile

from .exceptions import (
    ExemptionError,
    IllegalTransitionError,
    ResourceValidationError,
)
from .models import Exemption, ExemptionStatus, RejectReason, Resource
from .timeutil import parse_utc

_ALL = "*"
_ALLOWED_TRANSITIONS: dict[ExemptionStatus, frozenset[ExemptionStatus]] = {
    ExemptionStatus.PENDING: frozenset(
        {ExemptionStatus.ACTIVE, ExemptionStatus.REJECTED}
    ),
    ExemptionStatus.ACTIVE: frozenset({ExemptionStatus.REVOKED}),
    ExemptionStatus.REJECTED: frozenset(),
    ExemptionStatus.REVOKED: frozenset(),
}


def _scope_hit(values: list[str] | None, actual: str) -> bool:
    if values is None or len(values) == 0:
        return True
    if _ALL in values:
        return True
    return actual in values


def exemption_applies(
    exemption: Exemption, resource: Resource, rule_id: str, now
) -> bool:
    """范围与有效期命中（status 由调用方按 active 列表保证）。"""
    if not _scope_hit(exemption.rule_ids, rule_id):
        return False
    if not _scope_hit(exemption.kinds, resource.kind):
        return False
    if not _scope_hit(exemption.namespaces, resource.namespace):
        return False
    if exemption.resource_uids and not (
        _ALL in exemption.resource_uids or resource.uid in exemption.resource_uids
    ):
        return False
    start = parse_utc(exemption.valid_from, "valid_from")
    end = parse_utc(exemption.valid_until, "valid_until")
    if start > end:
        return False
    return start <= now <= end


@contextlib.contextmanager
def _file_lock(path: str):
    lock_path = path + ".lock"
    with open(lock_path, "w") as lock_fh:
        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)


def _exemption_to_dict(ex: Exemption) -> dict:
    return dataclasses.asdict(ex) | {"status": ex.status.value}


def _exemption_from_dict(data: dict) -> Exemption:
    return Exemption(
        id=data["id"],
        rule_ids=data.get("rule_ids"),
        kinds=data.get("kinds"),
        namespaces=data.get("namespaces"),
        resource_uids=data.get("resource_uids"),
        valid_from=data["valid_from"],
        valid_until=data["valid_until"],
        reason=data.get("reason", ""),
        status=ExemptionStatus(data["status"]),
        created_at=data["created_at"],
        updated_at=data["updated_at"],
    )


class ExemptionManager:
    def __init__(self, state_path: str) -> None:
        self._path = state_path
        os.makedirs(os.path.dirname(os.path.abspath(state_path)), exist_ok=True)
        if not os.path.exists(state_path):
            self._write_state({"exemptions": [], "idempotency": {}})

    def _read_state(self) -> dict:
        with open(self._path, encoding="utf-8") as fh:
            data = json.load(fh)
        data.setdefault("exemptions", [])
        data.setdefault("idempotency", {})
        return data

    def _write_state(self, state: dict) -> None:
        directory = os.path.dirname(os.path.abspath(self._path))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".exemptions-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(state, fh, ensure_ascii=False, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.remove(tmp)
            raise

    @staticmethod
    def validate_payload(payload: object) -> dict:
        """校验外部提交的豁免申请，返回规范化字典。"""
        if not isinstance(payload, dict):
            raise ResourceValidationError(
                RejectReason.RESOURCE_FIELD_MISSING, "豁免申请必须是 JSON 对象"
            )
        for key in ("id", "valid_from", "valid_until"):
            if not isinstance(payload.get(key), str) or not payload[key]:
                raise ResourceValidationError(
                    RejectReason.RESOURCE_FIELD_MISSING,
                    f"豁免申请缺少必填字符串字段: {key}",
                )
        for key in ("rule_ids", "kinds", "namespaces", "resource_uids"):
            value = payload.get(key)
            if value is not None and not (
                isinstance(value, list) and all(isinstance(v, str) and v for v in value)
            ):
                raise ResourceValidationError(
                    RejectReason.RESOURCE_FIELD_MISSING,
                    f"{key} 若提供必须是非空字符串数组",
                )
        if not isinstance(payload.get("reason", ""), str):
            raise ResourceValidationError(
                RejectReason.RESOURCE_FIELD_MISSING, "reason 必须是字符串"
            )
        start: object
        end: object
        try:
            start = parse_utc(payload["valid_from"], "valid_from")
            end = parse_utc(payload["valid_until"], "valid_until")
        except ValueError as exc:
            raise ResourceValidationError(
                RejectReason.RESOURCE_FIELD_MISSING, str(exc)
            ) from exc
        if start > end:
            raise ResourceValidationError(
                RejectReason.RESOURCE_FIELD_MISSING,
                "valid_from 不得晚于 valid_until",
            )
        return {
            "id": payload["id"],
            "rule_ids": payload.get("rule_ids"),
            "kinds": payload.get("kinds"),
            "namespaces": payload.get("namespaces"),
            "resource_uids": payload.get("resource_uids"),
            "valid_from": payload["valid_from"],
            "valid_until": payload["valid_until"],
            "reason": payload.get("reason", ""),
        }

    def submit(self, normalized: dict, now_iso: str, idempotency_key: str | None) -> Exemption:
        with _file_lock(self._path):
            state = self._read_state()
            if idempotency_key is not None:
                existing_id = state["idempotency"].get(idempotency_key)
                if existing_id is not None:
                    return self._find(state, existing_id)
            for item in state["exemptions"]:
                if item["id"] == normalized["id"]:
                    raise ExemptionError(
                        RejectReason.DUPLICATE_SUBMISSION_CONFLICT,
                        f"豁免 id 已存在: {normalized['id']}",
                    )
            exemption = Exemption(
                status=ExemptionStatus.PENDING,
                created_at=now_iso,
                updated_at=now_iso,
                **normalized,
            )
            state["exemptions"].append(_exemption_to_dict(exemption))
            if idempotency_key is not None:
                state["idempotency"][idempotency_key] = exemption.id
            self._write_state(state)
            return exemption

    def _transition(self, exemption_id: str, target: ExemptionStatus, now_iso: str) -> Exemption:
        with _file_lock(self._path):
            state = self._read_state()
            for item in state["exemptions"]:
                if item["id"] != exemption_id:
                    continue
                current = ExemptionStatus(item["status"])
                if target not in _ALLOWED_TRANSITIONS[current]:
                    raise IllegalTransitionError(
                        RejectReason.ILLEGAL_STATE_TRANSITION,
                        f"豁免 {exemption_id} 不允许从 {current.value} 流转到 {target.value}",
                    )
                item["status"] = target.value
                item["updated_at"] = now_iso
                self._write_state(state)
                return _exemption_from_dict(item)
            raise ExemptionError(
                RejectReason.EXEMPTION_NOT_FOUND, f"豁免不存在: {exemption_id}"
            )

    def activate(self, exemption_id: str, now_iso: str) -> Exemption:
        return self._transition(exemption_id, ExemptionStatus.ACTIVE, now_iso)

    def reject(self, exemption_id: str, now_iso: str) -> Exemption:
        return self._transition(exemption_id, ExemptionStatus.REJECTED, now_iso)

    def revoke(self, exemption_id: str, now_iso: str) -> Exemption:
        return self._transition(exemption_id, ExemptionStatus.REVOKED, now_iso)

    def get(self, exemption_id: str) -> Exemption:
        state = self._read_state()
        return self._find(state, exemption_id)

    @staticmethod
    def _find(state: dict, exemption_id: str) -> Exemption:
        for item in state["exemptions"]:
            if item["id"] == exemption_id:
                return _exemption_from_dict(item)
        raise ExemptionError(
            RejectReason.EXEMPTION_NOT_FOUND, f"豁免不存在: {exemption_id}"
        )

    def active_for(self, resource: Resource, now) -> list[Exemption]:
        """返回对该资源当前确实生效的 active 豁免（范围+有效期双重命中）。"""
        result: list[Exemption] = []
        for item in self._read_state()["exemptions"]:
            exemption = _exemption_from_dict(item)
            if exemption.status is not ExemptionStatus.ACTIVE:
                continue
            # 范围用通配规则粗筛；具体规则 id 在评估期判定。
            if not _scope_hit(exemption.kinds, resource.kind):
                continue
            if not _scope_hit(exemption.namespaces, resource.namespace):
                continue
            if exemption.resource_uids and not (
                _ALL in exemption.resource_uids
                or resource.uid in exemption.resource_uids
            ):
                continue
            start = parse_utc(exemption.valid_from, "valid_from")
            end = parse_utc(exemption.valid_until, "valid_until")
            if start <= now <= end:
                result.append(exemption)
        return result
