# container-policy-gate（本地容器合规准入服务）

一个完全本地运行的容器 / 云原生资源配置合规准入服务：用**本地策略文件**与**资源清单 JSON**
模拟 Kubernetes 风格的策略判定、豁免与准入流程。目标是让不同策略版本、不同并发提交下的
结论**一致、可解释、可复现**。

仅依赖 Python 标准库 + FastAPI（常规、可离线获取）；持久化只用本地 JSON 文件与文件锁，
无数据库、无网络依赖。

## 1. 运行与验证

```bash
# 安装依赖（需要 Python >= 3.14；uv 会自动创建 .venv）
uv sync

# 运行全部 45 个单测（日志会实时打印 输入 / 命中的策略版本 / 判定依据）
uv run pytest

# 启动 HTTP 服务（默认策略目录 data/policies，状态目录 data/state）
uv run uvicorn main:app --port 8000
# 可用环境变量覆盖：POLICYGATE_POLICY_DIR、POLICYGATE_STATE_DIR
```

策略与状态位置：

| 路径 | 说明 |
| --- | --- |
| `data/policies/policy-<version>.json` | 不可变策略版本文件，随仓库提供 v1、v2 两个示例 |
| `data/state/records.json` | 准入判定记录（只追加，历史不可变），运行时生成 |
| `data/state/exemptions.json` | 豁免申请与状态机数据，运行时生成 |
| `*.lock` | 与数据文件同名的 `flock` 锁，保证跨进程并发安全 |

## 2. 策略模型

### 2.1 策略文档

每个文件代表一个**不可变版本**，文件名版本必须与文档内 `version` 一致：

```json
{
  "version": "v2",
  "created_at": "2026-09-20T00:00:00Z",
  "rules": [
    {
      "id": "R-IMAGE-REGISTRY",
      "description": "镜像仓库必须在允许列表内",
      "match_kinds": ["Pod", "Deployment"],
      "field_path": "spec.image_repository",
      "operator": "in",
      "expected": ["registry.internal"],
      "severity": "critical",
      "on_violation": "reject"
    }
  ]
}
```

- `match_kinds`：按资源 `kind` 匹配，`"*"` 表示匹配全部；
- `field_path`：点分路径，**相对资源清单根**（如 `spec.image_repository`）；
- `operator`：`equals` / `not_equals` / `in` / `not_in` / `exists` / `not_exists`
  / `regex` / `less_than` / `greater_than`；
- `expected`：`in/not_in` 需要非空数组；`less_than/greater_than` 需要数值；
  `equals/not_equals` 接受标量；`regex` 需要可编译的正则字符串；`exists/not_exists` 不使用该字段；
- `severity`：`low | medium | high | critical`，只表示严重级别；
- `on_violation`：`warn`（告警但放行）或 `reject`（拒绝准入）——严重级别与处置结果相互独立。

整体结论聚合规则（`policygate/evaluator.py`）：

| 条件 | `decision` | `action` |
| --- | --- | --- |
| 存在未豁免的 `reject` 命中 | `reject` | `deny` |
| 仅有未豁免的 `warn` 命中 | `warn` | `allow` |
| 所有命中均被豁免（至少一条） | `exempted`/`warn`* | `allow` |
| 无任何命中 | `pass` | `allow` |

\* 当存在被豁免的 reject 命中、同时还有未豁免的 warn 命中时结论为 `warn`；
若所有命中都被豁免则为 `exempted`。

每条 `finding` 都带 `rule_id / severity / rule_decision / message / evidence / exempted_by`，
其中 `evidence` 是人类可读的判定依据（实际值 + 期望值），例如：

```
spec.image_repository='docker.io/x'，要求 in ['registry.internal']
必需字段 spec.cpu_limit 不存在
```

### 2.2 不可静默放行的三类失败（拒绝原因彼此可区分）

| HTTP `reason` 码 | 触发场景 |
| --- | --- |
| `policy_document_malformed` | 策略文件不是 JSON、文件名/文档版本不一致、缺必填字段、枚举非法、规则 id 重复等 |
| `rule_syntax_unsupported` | 操作符不在支持集合、字段路径非法、操作数类型错误、正则无法编译 |
| `resource_field_missing` | 资源清单缺 `apiVersion / kind / metadata.name` 等必填字段 |

另有业务拒绝码 `policy_violation`、`duplicate_submission_conflict`（HTTP 409）、
`illegal_state_transition`（HTTP 409）、`exemption_not_found`、`record_not_found`、
`exemption_scope_mismatch`、`exemption_expired` 等，均定义在 `policygate/models.py` 的
`RejectReason` 枚举中。

## 3. 豁免规则

豁免申请示例：

```json
{
  "id": "EX-1",
  "rule_ids": ["R-IMAGE-REGISTRY"],
  "kinds": ["Pod"],
  "namespaces": ["app"],
  "resource_uids": null,
  "valid_from": "2026-09-01T00:00:00Z",
  "valid_until": "2026-12-31T00:00:00Z",
  "reason": "仓库迁移期临时豁免"
}
```

- **生效范围**：四个维度（规则 / kind / namespace / 资源 uid）全部命中才生效；
  省略字段或 `["*"]` 表示该维度不限；
- **有效期**：闭区间 `[valid_from, valid_until]`，**必须显式携带时区**（`Z` 或 `+08:00`），
  避免无时区本地时间跨机器不一致；过期、未到生效时间均不采纳；
- 豁免只作用于**单条命中**（finding 上记录 `exempted_by`），不影响范围内不匹配的其他规则；
- 诊断接口 `POST /exemptions/check` 返回可区分的原因码：
  `exemption_applicable / exemption_not_active / exemption_expired /
  exemption_not_yet_valid / exemption_scope_mismatch`。

### 3.1 状态机

```
pending ──activate──▶ active ──revoke──▶ revoked   （终态）
   │                     │
   └──reject──▶ rejected ◀┘ 不允许                  （终态）
```

任何未列出的流转（如 `pending -> revoked`、重复 `activate`、对终态再操作）一律以
`illegal_state_transition` 拒绝（HTTP 409）。

## 4. 版本复现与不可变历史

- 每份策略文档在加载时计算 **SHA-256 内容指纹**（规范 JSON：键排序、紧凑分隔符、UTF-8，
  见 `policygate/fingerprints.py`）；资源清单同样计算指纹；
- 每次准入把 `policy_version`、`policy_fingerprint`、`resource_fingerprint`、完整结论
  （含逐条依据）**整体快照**写入只追加记录；
- `GET /resources/{uid}/replay[?record_id=...]` 是**直接回放历史快照**，绝不重新计算——
  即使后续策略升级（如 v2 收紧镜像白名单），历史判定仍按发生时的版本与指纹稳定复现，
  回放结果带 `replay=true`；
- 评估时也可显式指定版本：`POST /admit` 请求体中传 `"policy_version": "v1"`。

## 5. 并发与幂等

- 准入与豁免都支持 `idempotency_key`：相同 key 的重复提交返回首条记录，不产生重复记录或副作用；
  相同 key 但资源内容指纹不同，以 `duplicate_submission_conflict` 明确拒绝；
- 不传 key 时按 `资源uid|策略版本|资源指纹` 派生确定性 key；
- 两个 JSON 存储均采用 `flock(LOCK_EX)` + 临时文件 + `fsync` + `os.replace` 的读改写序列，
  多线程与多进程并发下最终状态唯一（见
  `tests/test_idempotency.py`、`tests/test_concurrency_multiprocess.py`）。

## 6. HTTP 接口一览

| 方法与路径 | 说明 |
| --- | --- |
| `GET /health` | 健康检查与已加载策略版本 |
| `POST /admit` | 提交资源清单做准入判定（可带 `idempotency_key`、`policy_version`） |
| `GET /resources/{uid}/history` | 某资源的全部历史判定 |
| `GET /resources/{uid}/replay` | 回放最近（或指定 `record_id`）的历史判定 |
| `POST /exemptions` | 提交豁免申请（可带 `idempotency_key`），初始为 `pending` |
| `POST /exemptions/{id}/transitions/{activate|reject|revoke}` | 豁免状态流转 |
| `POST /exemptions/check` | 诊断豁免对某资源是否生效及原因码 |

快速手工验证：

```bash
curl -s localhost:8000/health
curl -s -X POST localhost:8000/admit -H 'Content-Type: application/json' -d '{
  "idempotency_key": "demo-1",
  "apiVersion": "v1", "kind": "Pod",
  "metadata": {"name": "demo", "namespace": "app"},
  "spec": {"image_repository": "docker.io/x"}
}'
curl -s localhost:8000/resources/Pod/app/demo/replay
```

## 7. 代码结构

```
policygate/
  models.py         枚举与领域数据类型（含全部可区分 RejectReason）
  exceptions.py     携带原因码的领域异常
  fingerprints.py   规范 JSON 与 SHA-256 内容指纹
  timeutil.py       强制时区的 UTC 时间解析
  resources.py      资源清单解析与必填字段校验
  policy_store.py   多版本策略加载、严格校验、指纹管理
  evaluator.py      规则匹配 / 操作符判定 / 豁免适用 / 结论聚合
  exemptions.py     豁免范围、有效期、状态机、幂等持久化
  records.py        不可变准入记录、幂等去重、并发安全
  serialization.py  领域对象 -> JSON
  service.py        编排：评估、幂等落库、历史复现、豁免流转
  api.py            FastAPI 路由与错误码 -> HTTP 映射
tests/              45 个单测：畸形策略 / 越界过期豁免 / 并发重复提交 / 版本复现 / API
data/policies/      示例策略 v1、v2
```
