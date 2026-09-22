"""准入记录存储。

- 历史结论不可变：记录只追加，不提供修改；
- 幂等：相同 idempotency_key 返回既有记录；相同 key 但资源内容不同 ->
  DUPLICATE_SUBMISSION_CONFLICT（明确拒绝，避免同一凭据绑定不同资源）；
- 并发：文件锁 + 读改写 + os.replace，多进程/多线程下 put_if_absent 原子。
"""
from __future__ import annotations

import contextlib
import dataclasses
import fcntl
import json
import os
import tempfile

from .exceptions import IdempotencyConflictError
from .models import (
    AdmissionAction,
    AdmissionRecord,
    EvaluationResult,
    Finding,
    OverallDecision,
    RejectReason,
    RuleDecision,
    Severity,
)


@contextlib.contextmanager
def _file_lock(path: str):
    lock_path = path + ".lock"
    with open(lock_path, "w") as lock_fh:
        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)


def _finding_to_dict(f: Finding) -> dict:
    return dataclasses.asdict(f) | {
        "severity": f.severity.value,
        "rule_decision": f.rule_decision.value,
    }


def _finding_from_dict(d: dict) -> Finding:
    return Finding(
        rule_id=d["rule_id"],
        severity=Severity(d["severity"]),
        rule_decision=RuleDecision(d["rule_decision"]),
        message=d["message"],
        evidence=d["evidence"],
        exempted_by=d.get("exempted_by"),
    )


def _result_to_dict(r: EvaluationResult) -> dict:
    data = dataclasses.asdict(r)
    data["decision"] = r.decision.value
    data["action"] = r.action.value
    data["findings"] = [_finding_to_dict(f) for f in r.findings]
    return data


def _result_from_dict(d: dict) -> EvaluationResult:
    return EvaluationResult(
        resource_uid=d["resource_uid"],
        resource_fingerprint=d["resource_fingerprint"],
        policy_version=d["policy_version"],
        policy_fingerprint=d["policy_fingerprint"],
        decision=OverallDecision(d["decision"]),
        action=AdmissionAction(d["action"]),
        findings=[_finding_from_dict(f) for f in d["findings"]],
        evaluated_at=d["evaluated_at"],
        replay=d.get("replay", False),
    )


def _record_to_dict(rec: AdmissionRecord) -> dict:
    return {
        "idempotency_key": rec.idempotency_key,
        "resource_uid": rec.resource_uid,
        "result": _result_to_dict(rec.result),
        "created_at": rec.created_at,
    }


def _record_from_dict(d: dict) -> AdmissionRecord:
    return AdmissionRecord(
        idempotency_key=d["idempotency_key"],
        resource_uid=d["resource_uid"],
        result=_result_from_dict(d["result"]),
        created_at=d["created_at"],
    )


class RecordStore:
    def __init__(self, state_path: str) -> None:
        self._path = state_path
        os.makedirs(os.path.dirname(os.path.abspath(state_path)), exist_ok=True)
        if not os.path.exists(state_path):
            self._write_state({"records": [], "keys": {}})

    def _read_state(self) -> dict:
        with open(self._path, encoding="utf-8") as fh:
            data = json.load(fh)
        data.setdefault("records", [])
        data.setdefault("keys", {})
        return data

    def _write_state(self, state: dict) -> None:
        directory = os.path.dirname(os.path.abspath(self._path))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".records-", suffix=".tmp")
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

    def get_by_idempotency_key(self, key: str) -> AdmissionRecord | None:
        state = self._read_state()
        rec_id = state["keys"].get(key)
        if rec_id is None:
            return None
        for item in state["records"]:
            if item["idempotency_key"] == key:
                return _record_from_dict(item)
        return None

    def put_if_absent(
        self, record: AdmissionRecord, resource_fingerprint: str
    ) -> AdmissionRecord:
        """原子写入。key 已存在时：内容一致返回旧记录，不一致抛冲突。"""
        with _file_lock(self._path):
            state = self._read_state()
            for item in state["records"]:
                if item["idempotency_key"] == record.idempotency_key:
                    existing_fp = item["result"]["resource_fingerprint"]
                    if existing_fp != resource_fingerprint:
                        raise IdempotencyConflictError(
                            RejectReason.DUPLICATE_SUBMISSION_CONFLICT,
                            "同一 idempotency_key 对应不同资源内容，拒绝重复提交",
                        )
                    return _record_from_dict(item)
            state["records"].append(_record_to_dict(record))
            state["keys"][record.idempotency_key] = record.idempotency_key
            self._write_state(state)
            return record

    def get_resource_history(self, resource_uid: str) -> list[AdmissionRecord]:
        state = self._read_state()
        items = [
            _record_from_dict(item)
            for item in state["records"]
            if item["resource_uid"] == resource_uid
        ]
        items.sort(key=lambda r: (r.created_at, r.idempotency_key))
        return items

    def get(self, idempotency_key: str) -> AdmissionRecord:
        record = self.get_by_idempotency_key(idempotency_key)
        if record is None:
            raise IdempotencyConflictError(
                RejectReason.RECORD_NOT_FOUND,
                f"准入记录不存在: {idempotency_key}",
            )
        return record
