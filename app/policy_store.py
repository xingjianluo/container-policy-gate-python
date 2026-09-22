"""策略仓库：版本化、内容指纹、不可变。

- 策略以 (name, version) 唯一标识；
- 每个版本保留原始文档、归一化规则与 sha256 内容指纹；
- 新版本号必须严格递增（显式取 max+1 或文档内 version 均可，
  这里以文档内 version 为准），并发/重复发布冲突时抛 PolicyVersionConflict；
- 历史版本永不被覆盖；判定记录引用版本号 + 指纹实现复现。
"""

from __future__ import annotations

from typing import Any

from .clock import Clock, SystemClock, to_iso
from .errors import PolicyDocumentError, PolicyVersionConflict
from .models import Policy, Rule
from .policy_parser import parse_document
from .resource import fingerprint
from .storage import JsonStore

_DEFAULT_DATA: dict[str, Any] = {"policies": {}}


class PolicyStore:
    """策略版本仓库，底层文件形如 {"policies": {name: {str(version): record}}}}。"""

    def __init__(self, store: JsonStore, clock: Clock | None = None) -> None:
        self._store = store
        self._clock = clock or SystemClock()

    def publish(self, document: dict[str, Any] | str | bytes) -> Policy:
        """解析并发布一个新版本。

        版本号必须恰好等于该策略当前最大版本 + 1（首个版本为 1），
        从而拒绝回退、跳号与并发覆盖。
        """
        name, version, rules, description = parse_document(document)
        raw_obj = document if isinstance(document, dict) else _to_obj(document)
        # 指纹同时覆盖原始文档与归一化规则：任何一处被篡改都会导致指纹不符
        fp = fingerprint(
            {
                "raw_document": raw_obj,
                "rules": [_rule_to_dict(r) for r in rules],
            }
        )
        created_at = to_iso(self._clock.now())

        with self._store.mutate() as data:
            bucket = data.setdefault("policies", {}).setdefault(name, {})
            if str(version) in bucket:
                raise PolicyVersionConflict(
                    f"策略 {name} 版本 {version} 已存在（内容指纹 {fp[:12]}），"
                    "历史版本不可覆盖",
                    {"name": name, "version": version},
                )
            existing_versions = [int(v) for v in bucket if v.isdigit()]
            expected = (max(existing_versions) + 1) if existing_versions else 1
            if version != expected:
                raise PolicyVersionConflict(
                    f"策略 {name} 的下一个版本必须是 {expected}，收到 {version}",
                    {"name": name, "expected": expected, "received": version},
                )
            bucket[str(version)] = {
                "name": name,
                "version": version,
                "fingerprint": fp,
                "description": description,
                "created_at": created_at,
                "raw_document": document if isinstance(document, dict) else _to_obj(document),
                "rules": [_rule_to_dict(r) for r in rules],
            }

        return self.get(name, version)

    def get(self, name: str, version: int) -> Policy | None:
        """按版本号获取策略；不存在返回 None。"""
        data = self._store.load()
        record = data.get("policies", {}).get(name, {}).get(str(version))
        return _record_to_policy(record) if record else None

    def latest(self, name: str) -> Policy | None:
        """获取指定策略的最新版本。"""
        data = self._store.load()
        bucket = data.get("policies", {}).get(name, {})
        if not bucket:
            return None
        latest_version = max(int(v) for v in bucket if v.isdigit())
        return _record_to_policy(bucket[str(latest_version)])

    def get_for_replay(self, name: str, version: int, content_fingerprint: str) -> Policy:
        """按 版本+指纹 取回用于复现的策略；指纹不匹配则拒绝。

        指纹从磁盘上的原始文档+归一化规则当场重算，与判定记录中固化的
        （不可变）指纹比对；即使有人连策略文件里的 fingerprint 字段一起改，
        也无法伪造一致结论。
        """
        policy = self.get(name, version)
        if policy is None:
            raise PolicyDocumentError(
                f"复现失败：策略 {name} 版本 {version} 不存在",
                {"name": name, "version": version},
            )
        if policy.fingerprint != content_fingerprint:
            raise PolicyVersionConflict(
                f"复现失败：策略 {name} v{version} 的内容指纹与判定记录不一致，"
                "历史策略内容疑似被篡改",
                {
                    "name": name,
                    "version": version,
                    "recorded_fingerprint": content_fingerprint,
                    "current_fingerprint": policy.fingerprint,
                },
            )
        return policy

    def _raw_record(self, name: str, version: int) -> dict[str, Any] | None:
        data = self._store.load()
        return data.get("policies", {}).get(name, {}).get(str(version))

    def fingerprint_on_disk(self, name: str, version: int) -> str | None:
        """从磁盘内容当场重算指定版本的指纹；版本不存在返回 None。"""
        record = self._raw_record(name, version)
        if record is None:
            return None
        return fingerprint(
            {"raw_document": record.get("raw_document", {}), "rules": record["rules"]}
        )

    def versions(self, name: str) -> list[int]:
        """列出策略全部版本号（升序）。"""
        data = self._store.load()
        return sorted(
            int(v) for v in data.get("policies", {}).get(name, {}) if v.isdigit()
        )


def _to_obj(raw: str | bytes) -> dict[str, Any]:
    import json

    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise PolicyDocumentError("策略文档根节点必须是 JSON 对象")
    return obj


def _rule_to_dict(rule: Rule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "description": rule.description,
        "match": rule.match,
        "field": rule.field,
        "operator": rule.operator,
        "value": rule.value,
        "severity": rule.severity.value,
        "on_violation": rule.on_violation,
    }


def _record_to_policy(record: dict[str, Any]) -> Policy:
    from .models import Severity

    rules = tuple(
        Rule(
            id=r["id"],
            description=r.get("description", ""),
            match=r.get("match", {}),
            field=r["field"],
            operator=r["operator"],
            value=r.get("value"),
            severity=Severity(r["severity"]),
            on_violation=r.get("on_violation", "deny"),
        )
        for r in record["rules"]
    )
    # 指纹永远从内容当场重算，不信任文件里可被一并篡改的 fingerprint 字段；
    # 与历史判定记录中固化的指纹是否一致，由 get_for_replay 负责比对。
    computed = fingerprint(
        {"raw_document": record.get("raw_document", {}), "rules": record["rules"]}
    )
    return Policy(
        name=record["name"],
        version=record["version"],
        fingerprint=computed,
        rules=rules,
        created_at=record.get("created_at", ""),
        description=record.get("description", ""),
    )
