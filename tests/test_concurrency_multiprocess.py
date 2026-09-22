"""跨进程并发：fcntl 文件锁必须保证多进程下幂等键唯一。"""
from __future__ import annotations

import json
import multiprocessing as mp


def _admit(policy_dir: str, state_dir: str):
    from policygate.service import GateService

    svc = GateService(policy_dir, state_dir)
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": "mp", "namespace": "app"},
           "spec": {"image_repository": "docker.io/x"}}
    svc.admit(pod, idempotency_key="mp-key")


def test_multiprocess_same_key_single_record(tmp_path):
    policy_dir = tmp_path / "p"
    policy_dir.mkdir()
    v1 = {
        "version": "v1", "created_at": "2026-09-01T00:00:00Z",
        "rules": [
            {"id": "R1", "description": "x", "match_kinds": ["Pod"],
             "field_path": "spec.image_repository", "operator": "in",
             "expected": ["registry.internal"],
             "severity": "high", "on_violation": "reject"},
        ],
    }
    (policy_dir / "policy-v1.json").write_text(json.dumps(v1), encoding="utf-8")
    state_dir = tmp_path / "s"
    state_dir.mkdir()

    ctx = mp.get_context("fork")
    procs = [
        ctx.Process(target=_admit, args=(str(policy_dir), str(state_dir)))
        for _ in range(8)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join()
        assert p.exitcode == 0

    from policygate.records import RecordStore

    store = RecordStore(str(state_dir / "records.json"))
    records = store.get_resource_history("Pod/app/mp")
    assert len(records) == 1
    assert records[0].idempotency_key == "mp-key"
