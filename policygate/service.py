"""应用服务：编排策略加载、资源解析、豁免筛选、评估、幂等落库与历史复现。"""
from __future__ import annotations

import dataclasses
import hashlib

from .evaluator import Evaluator
from .exemptions import ExemptionManager
from .models import AdmissionRecord
from .policy_store import PolicyStore
from .records import RecordStore
from .resources import parse_resource, resource_fingerprint
from .serialization import exemption_to_dict, result_to_dict
from .timeutil import now_utc, parse_utc, to_iso_z


class GateService:
    def __init__(self, policy_dir: str, state_dir: str) -> None:
        self.policy_store = PolicyStore(policy_dir)
        self.exemptions = ExemptionManager(f"{state_dir}/exemptions.json")
        self.records = RecordStore(f"{state_dir}/records.json")
        self.evaluator = Evaluator()

    @staticmethod
    def _default_idempotency_key(resource, policy_version: str, fp: str) -> str:
        digest = hashlib.sha256(f"{resource.uid}|{policy_version}|{fp}".encode()).hexdigest()
        return f"auto-{digest[:32]}"

    def admit(
        self,
        resource_dict: dict,
        idempotency_key: str | None = None,
        policy_version: str | None = None,
    ) -> dict:
        resource = parse_resource(resource_dict)
        version = policy_version or self.policy_store.latest_version()
        policy = self.policy_store.get(version)
        policy_fp = self.policy_store.fingerprint_of(version)
        fp = resource_fingerprint(resource)
        key = idempotency_key or self._default_idempotency_key(resource, version, fp)

        existing = self.records.get_by_idempotency_key(key)
        if existing is not None:
            if existing.result.resource_fingerprint != fp:
                from .exceptions import IdempotencyConflictError
                from .models import RejectReason

                raise IdempotencyConflictError(
                    RejectReason.DUPLICATE_SUBMISSION_CONFLICT,
                    "同一 idempotency_key 对应不同资源内容，拒绝重复提交",
                )
            return {
                "idempotency_key": key,
                "replayed_from_history": True,
                "result": result_to_dict(existing.result),
            }

        now = now_utc()
        active = self.exemptions.active_for(resource, now)
        result = self.evaluator.evaluate(
            resource=resource,
            policy=policy,
            policy_fingerprint=policy_fp,
            active_exemptions=active,
            now=now,
            evaluated_at=to_iso_z(now),
        )
        record = AdmissionRecord(
            idempotency_key=key,
            resource_uid=resource.uid,
            result=result,
            created_at=to_iso_z(now),
        )
        stored = self.records.put_if_absent(record, fp)
        return {
            "idempotency_key": key,
            "replayed_from_history": stored is not record,
            "result": result_to_dict(stored.result),
        }

    def replay(self, resource_uid: str, record_id: str | None = None) -> dict:
        """按历史记录复现：直接回放存储时的策略版本/指纹/结论，绝不重新计算覆盖。"""
        history = self.records.get_resource_history(resource_uid)
        if record_id is not None:
            matched = [r for r in history if r.idempotency_key == record_id]
            if not matched:
                from .exceptions import IdempotencyConflictError
                from .models import RejectReason

                raise IdempotencyConflictError(
                    RejectReason.RECORD_NOT_FOUND,
                    f"资源 {resource_uid} 没有记录 {record_id}",
                )
            record = matched[0]
        else:
            if not history:
                from .exceptions import IdempotencyConflictError
                from .models import RejectReason

                raise IdempotencyConflictError(
                    RejectReason.RECORD_NOT_FOUND,
                    f"资源没有任何历史判定: {resource_uid}",
                )
            record = history[-1]
        result = dataclasses.replace(record.result, replay=True)
        return {
            "idempotency_key": record.idempotency_key,
            "replayed_from_history": True,
            "result": result_to_dict(result),
        }

    def history(self, resource_uid: str) -> list[dict]:
        return [
            {
                "idempotency_key": r.idempotency_key,
                "created_at": r.created_at,
                "result": result_to_dict(r.result),
            }
            for r in self.records.get_resource_history(resource_uid)
        ]

    def submit_exemption(self, payload: dict, idempotency_key: str | None = None) -> dict:
        normalized = self.exemptions.validate_payload(payload)
        exemption = self.exemptions.submit(normalized, to_iso_z(now_utc()), idempotency_key)
        return exemption_to_dict(exemption)

    def transition_exemption(self, exemption_id: str, action: str) -> dict:
        now_iso = to_iso_z(now_utc())
        method = {
            "activate": self.exemptions.activate,
            "reject": self.exemptions.reject,
            "revoke": self.exemptions.revoke,
        }.get(action)
        if method is None:
            from .exceptions import IllegalTransitionError
            from .models import RejectReason

            raise IllegalTransitionError(
                RejectReason.ILLEGAL_STATE_TRANSITION,
                f"未知豁免流转动作: {action}",
            )
        return exemption_to_dict(method(exemption_id, now_iso))

    def check_exemption(self, payload: dict) -> dict:
        """诊断接口：说明一份豁免为何生效或不生效，原因彼此可区分。"""
        resource = parse_resource(payload["resource"])
        exemption = self.exemptions.get(payload["exemption_id"])
        now = now_utc()
        if exemption.status.value != "active":
            code = "exemption_not_active"
        elif now > parse_utc(exemption.valid_until, "valid_until"):
            code = "exemption_expired"
        elif now < parse_utc(exemption.valid_from, "valid_from"):
            code = "exemption_not_yet_valid"
        elif not self.exemptions.active_for(resource, now):
            code = "exemption_scope_mismatch"
        else:
            code = "exemption_applicable"
        return {
            "exemption_id": exemption.id,
            "status": exemption.status.value,
            "reason_code": code,
        }
