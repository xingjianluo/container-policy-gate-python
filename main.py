"""本地开发入口：uvicorn main:app --reload。

数据目录可用环境变量 POLICY_GATE_DATA_DIR 覆盖（默认 ./data）。
"""

import os

from app.app import create_app
from app.service import Container

container = Container.create(data_dir=os.environ.get("POLICY_GATE_DATA_DIR", "data"))
app = create_app(container)
