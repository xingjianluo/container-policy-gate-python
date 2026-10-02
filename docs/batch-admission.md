# 批量准入与重复上报收口

上游巡检流水线一次上报一整组资源清单，且多个定时任务在网络抖动时会
不带幂等标识地重试同一份内容。本文档说明批量准入的语义、重复上报时
结果复用的边界，以及批次与策略版本的对应关系。

## 批量准入语义

`POST /api/admit/batch`，请求体：

```json
{
  "resources": [{ "...资源清单..." }, { "...资源清单..." }],
  "policy_name": "default",
  "policy_version": 1
}
```

- **逐条结论**：响应 `items[]` 按提交顺序给出每条资源的结论——
  处置动作（`action`）、命中的规则与判定依据（`hits[].reason`）、
  以及该条是否复用了既有判定（`reused`）。
- **整批汇总**：`summary` 给出总数、各处置动作计数、不合法条数与
  整体处置（任一拒绝则整批 `deny`；存在不合法条目时至少按
  `allow_with_warning` 对待，保证不合法在汇总层面可见）。
- **个别不合法不拖垮整批**：单条资源字段缺失或内容不合法时，该条
  标记为 `status=invalid` 并附带可区分的错误原因
  （`error.error=resource_validation_failed` 及明细），其余合法资源
  照常出结论。不合法条目**不会**被静默放行：它不产生判定记录，
  且计入 `summary.invalid`。
- **顺序无关**：批次指纹由排序后的条目内容指纹计算，同一批资源换个
  顺序提交，得到同一个 `batch_id` 与同一份汇总。
- **规模**：上百条的批次可稳定跑完；每个资源内容恰好对应一条判定
  记录，不重不漏（见 `test_large_batch_stable_no_duplicate_no_missing`）。

## 重复上报的复用边界

判定记录按两级键去重，全部在存储层锁内做最终裁决，串行重试与
多进程/多线程并发提交结果一致：

### 什么算"同一份"（复用既有结论，不产生新记录）

- 调用方提供了 `idempotency_key`：键相同即同一次提交（键优先，
  首决确定性——即使内容不同也以首次为准）。
- 调用方**不带**幂等标识：**资源内容指纹相同 + 策略名称、版本号与
  策略内容指纹都相同**，即视为同一次上报，复用既有判定。
  单条响应标记 `content_reused: true`，批量条目标记 `reused: true`，
  返回中的 `decision_id` 即被复用的结论。
- 整批重复提交：批次内容指纹（排序后的条目指纹 + 策略版本指纹）
  相同即同一个批次，返回首次批次的 `batch_id` 与汇总，
  响应标记 `reused: true`。批次里只有一部分条目此前判过时，
  已判条目逐条复用、新条目正常判定，不产生重复记录也不漏条目。

### 什么算"新提交"（必须重新判定，不得复用）

- 资源清单**内容有任何改动**（内容指纹变化）；
- **策略版本变化**：发布了新版本后最新版指针移动，或显式指定了
  不同的 `policy_version`；即使版本号相同，策略内容指纹不同也算新提交；
- 显式提供了**不同的** `idempotency_key`（视为调用方有意区分的多次判定）。

## 批次与策略版本的对应关系

- 进入批次时**选定一次**策略版本（显式 `policy_version` 或当时最新版），
  整批所有条目都落在这一份快照上；批次执行期间有人发布新版本，
  不影响本批——不会出现一批里有的按旧版判、有的按新版判。
- 批次响应携带本批使用的 `policy.name / version / fingerprint`，
  每条判定记录同样固化版本号与内容指纹。
- 批次中每条判定记录之后都可用
  `POST /api/decisions/{decision_id}/replay` 单独复现：按记录的
  版本+指纹取回历史策略重算并逐字段比对，结果稳定一致。

## 本地复现与验证

```bash
uv sync
uv run uvicorn main:app --reload
```

发布策略后批量提交：

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
# 第二条缺必填字段 -> items[1].status == "invalid"，其余照常出结论
# 再执行一次同一请求 -> reused: true，batch_id 与汇总不变
```

运行测试（`-s` 打印每条用例的业务场景、策略版本与判定依据）：

```bash
uv run pytest -s
# 只看批量与重复上报相关用例
uv run pytest tests/test_batch.py -s
```

覆盖：批量提交与汇总、换序一致性、串行/并发无键重复上报、
批次混入不合法资源、批次执行中策略版本变化、内容/版本变更算新提交、
120 条大批量、HTTP 端到端。
