"""应用装配：统一构造存储、时钟与领域服务。

数据目录可在测试中替换为 tmp_path，实现完全离线、用例间互不干扰。
三个 JsonStore 各自独立文件、独立锁；判定与豁免的状态一致性由
各自的 mutate() 临界区保证，跨存储的最终一致通过“先评估后落盘”
与幂等键去重实现（重复提交不会产生重复副作用）。
"""

from __future__ import annotations

from pathlib import Path

from .clock import Clock, SystemClock
from .decision_store import DecisionStore
from .evaluator import Evaluator
from .exemption import ExemptionService
from .policy_store import PolicyStore
from .storage import JsonStore


class Container:
    """服务容器：持有全部组件与底层存储句柄。"""

    def __init__(self, data_dir: str | Path = "data", clock: Clock | None = None) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.clock: Clock = clock or SystemClock()

        self.policy_json_store = JsonStore(self.data_dir / "policies.json")
        self.decision_json_store = JsonStore(self.data_dir / "decisions.json")
        self.exemption_json_store = JsonStore(self.data_dir / "exemptions.json")

        self.policy_store = PolicyStore(self.policy_json_store, self.clock)
        self.decision_store = DecisionStore(self.decision_json_store)
        self.exemption_service = ExemptionService(self.exemption_json_store, self.clock)
        self.evaluator = Evaluator(
            self.policy_store,
            self.decision_store,
            self.exemption_service,
            self.clock,
        )

    @classmethod
    def create(cls, data_dir: str | Path = "data", clock: Clock | None = None) -> Container:
        """工厂方法（与构造器等价，保留给未来做预热/迁移）。"""
        return cls(data_dir=data_dir, clock=clock)
