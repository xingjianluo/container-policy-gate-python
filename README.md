# Container Policy Gate（本地容器合规准入服务）

用**本地策略文件 + 资源清单**模拟 Kubernetes 风格的准入控制（admission）：
对容器/云原生资源清单按版本化策略进行合规判定，支持豁免、幂等并发提交，
并保证不同策略版本、并发提交下的结论**一致、可解释、可复现**。

- 仅依赖本地 JSON 文件、Python 标准库（`fcntl`/`threading`/`hashlib` 等）
  与 FastAPI；无外部数据库，无网络调用，可完全离线运行与测试。
- Python >= 3.14，使用 [uv](https://github.com/astral-sh/uv) 管理环境。

## 目录结构

```
app/
├── errors.py          # 可区分的错误码（畸形策略/不支持语法/字段缺失/越界/过期/非法流转…）
├── clock.py           # 可注入时钟（测试可冻结/拨快时间）
├── models.py          # 领域模型：severity / verdict / action / rule / decision / hit
├── operators.py       # 规则算子（eq/ne/in/regex/present/…）
├── resource.py        # 资源校验、字段路径、选择器匹配、内容指纹
├── policy_parser.py   # 策略文档解析（严格区分文档错误与规则语法错误）
├── policy_store.py    # 策略版本仓库（不可变、版本递增、指纹）
├── exemption.py       # 豁免：范围 + 有效期 + 状态机 + 幂等
├── decision_store.py  # 判定记录仓库（不可变、幂等键 + 内容指纹去重）
├── evaluator.py       # 评估引擎与历史复现 replay
├── batch.py           # 批量准入（同一策略快照、逐条结论、整批汇总）
├── batch_store.py     # 批量判定记录仓库（按批次内容指纹去重）
├── storage.py         # JSON 文件存储（原子写 + 线程锁 + fcntl 跨进程锁）
├── service.py         # 组件装配容器
├── api.py             # HTTP 路由
├── app.py             # FastAPI 工厂与错误映射
data/sample-policy.json# 示例策略
docs/                  # 策略模型 / 豁免规则 / 版本复现 / 批量准入与重复上报
tests/                 # 97 个测试（畸形策略、越界/过期豁免、并发重复提交、批量准入…）
```

详细设计见：
[`docs/policy-model.md`](docs/policy-model.md)、
[`docs/exemption.md`](docs/exemption.md)、
[`docs/versioning-and-replay.md`](docs/versioning-and-replay.md)、
[`docs/batch-admission.md`](docs/batch-admission.md)。

## 快速开始

```bash
uv sync                 # 离线安装依赖（含 pytest/httpx 开发依赖）
uv run uvicorn main:app --reload
# 打开 http://127.0.0.1:8000/docs
```

### 1) 发布策略（版本化、不可变）

```bash
curl -s -X POST localhost:8000/api/policies \
  -H 'content-type: application/json' \
  --data @<(jq -c '{document: .}' data/sample-policy.json)
```

返回该版本的 `version` 与 `fingerprint`。重复发布同一版本、跳号或回退都会
收到 `409 policy_version_conflict`。

### 2) 提交资源清单做准入判定

```bash
curl -s -X POST localhost:8000/api/admit -H 'content-type: application/json' -d '{
  "resource": {
    "apiVersion": "apps/v1", "kind": "Deployment",
    "metadata": {"name": "web", "namespace": "prod"},
    "spec": {"image": "nginx:latest"}
  },
  "policy_name": "default",
  "idempotency_key": "deploy-web-001"
}'
```

结论示例（节选）：

```json
{
  "action": "deny",
  "policy": {"name": "default", "version": 1, "fingerprint": "…"},
  "rationale": "拒绝：命中 1 条未豁免违规（最高严重级别 high，规则 image-fixed-tag）；另有 1 条告警/豁免",
  "hits": [
    {"rule_id": "image-fixed-tag", "verdict": "violation", "severity": "high",
     "actual": "nginx:latest", "exempted": false,
     "reason": "命中违规：字段 spec.image='nginx:latest' 不满足 regex …，且无有效豁免"}
  ]
}
```

同一 `idempotency_key` 再提交一次，返回同一条记录且 `idempotent_hit: true`，
不产生重复记录。**不带幂等标识**时，同一份资源内容在同一策略版本下重复
提交也会自动复用既有结论（`content_reused: true`）；内容或策略版本有
变化则视为新判定。

### 3) 批量提交一组资源清单

```bash
curl -s -X POST localhost:8000/api/admit/batch -H 'content-type: application/json' -d '{
  "policy_name": "default",
  "resources": [
    {"apiVersion":"apps/v1","kind":"Deployment",
     "metadata":{"name":"web","namespace":"prod"},
     "spec":{"image":"nginx:latest"}},
    {"kind":"Pod"}
  ]
}'
```

- 整批落在**同一个策略快照**上，响应携带本批 `policy.version/fingerprint`；
- `items[]` 逐条给出结论、命中规则与判定依据；不合法的条目单独标记
  `status=invalid` 及原因，不拖垮整批、也不静默放行；
- `summary` 汇总整批结论，与提交顺序无关；同一批重复提交返回同一
  `batch_id` 并标记 `reused: true`；换序重交时 `items[]` 仍按**本次**
  提交顺序逐条对齐（不合法条目也落回它本次的位置）。

语义细节见 [`docs/batch-admission.md`](docs/batch-admission.md)。

### 4) 申请并批准豁免

```bash
# 申请（范围 prod/web，仅豁免 image-fixed-tag，两小时有效）
curl -s -X POST localhost:8000/api/exemptions -H 'content-type: application/json' -d '{
  "scope": {"kind":"Deployment","namespace":"prod","name":"web"},
  "rule_ids": ["image-fixed-tag"],
  "valid_from": "2026-09-23T09:00:00Z",
  "valid_until": "2026-09-23T11:00:00Z",
  "reason": "发布窗口", "idempotency_key": "ex-web-001"
}'
# 用返回的 exemption_id 批准
curl -s -X POST localhost:8000/api/exemptions/<id>/approve
```

此后同一资源的判定变为 `allow_with_warning`（违规仍如实记录，`exempted=true`）。
豁免过期/越界/未批准都不会被采纳；撤销走 `/revoke`。

### 5) 历史复现

```bash
curl -s -X POST localhost:8000/api/decisions/<decision_id>/replay
# {"consistent": true, "policy_version": 1, "stored": {...}, "recomputed": {...}}
```

即使之后发布了 v2 策略，历史判定仍按 v1 的内容与指纹复现；
策略文件被篡改导致指纹不符时，复现被明确拒绝。

## 错误码（拒绝原因彼此可区分，绝不静默放行）

| code | 含义 |
|---|---|
| `policy_document_invalid` | 策略文档格式/结构错误 |
| `unsupported_rule_syntax` | 规则算子/字段语法不受支持 |
| `resource_validation_failed` | 资源必填字段缺失或类型错 |
| `policy_version_conflict` | 版本冲突/跳号/历史指纹不符 |
| `exemption_expired` | 豁免已过期或尚未生效 |
| `exemption_out_of_scope` | 豁免不在生效范围内 |
| `illegal_state_transition` | 豁免状态非法流转 |
| `duplicate_submission` / `not_found` / `exemption_not_found` / `storage_error` | 其他 |

## 验证方法

```bash
uv run pytest -s
```

- `-s` 会打印测试日志：每个关键用例都输出**输入资源/文档、命中的策略版本、
  内容指纹与判定依据**（logger `policy_gate.evaluator`）。
- 覆盖范围：
  - 畸形策略 JSON、未知算子/非法正则/非法路径、资源必填字段缺失（三类错误码断言）；
  - 豁免范围越界（namespace/name/labels/rule_ids）、过期与未生效、未批准与撤销；
  - 非法状态流转（requested→revoked、重复 approve、终态再流转）；
  - 16 线程并发同键准入、12 线程并发同键豁免申请、并发 approve/reject 只有一个成功；
  - 批量准入：逐条结论与整批汇总、换序一致、混入不合法资源单独标记；
  - 换序/重复提交时逐条结果按本次提交顺序对齐（含不合法条目落回原位、
    批内重复条目、多定时任务并发换序同批）；
  - 无幂等标识重复上报收口：串行/并发同内容只留一条，整批重复提交复用首次汇总；
  - 批次执行中发布新策略版本，整批仍按进入时的快照判定；
  - 内容或策略版本变化算新提交，不错误复用；120 条大批量不重不漏；
  - 策略升级 v2 后历史判定按 v1 复现、跨进程重启后复现、篡改策略文件指纹被拒；
  - 全量 HTTP 端到端流程。
