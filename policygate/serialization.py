"""领域对象 -> 纯 JSON 字典（枚举显式转为 value，避免依赖 str-Enum 的隐式行为）。"""
from __future__ import annotations

import dataclasses


def finding_to_dict(f) -> dict:
    return dataclasses.asdict(f) | {
        "severity": f.severity.value,
        "rule_decision": f.rule_decision.value,
    }


def result_to_dict(result) -> dict:
    data = dataclasses.asdict(result)
    data["decision"] = result.decision.value
    data["action"] = result.action.value
    data["findings"] = [finding_to_dict(f) for f in result.findings]
    return data


def exemption_to_dict(ex) -> dict:
    return dataclasses.asdict(ex) | {"status": ex.status.value}
