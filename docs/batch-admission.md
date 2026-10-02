# 批量准入与同内容重复上报

在单条准入（`/api/admit`）之上，系统提供批量准入（`/api/admit/batch`），
并对"调用方不带幂等标识、同内容被反复上报"的场景做了自动收口。

## 批量准入语义

```bash
curl -s -X POST localhost:8000/api/admit/batch -H 'content-type: application/json' -d '{
  "policy_name": "default",
  "resources": [ {"apiVersion":"apps/v1","kind":"Deployment", ...}, ... ]
}'
```

- 一次请求携带一组资源清单，返回 `items` 与请求顺序一一对应：
  每条给出结论（`decision.action`）、命中的规则与判定依据（`decision.hits[].reason`）；
  `summary` 给出整批汇总（各处置计数 + `overall_action` 汇总结论）。
- **单条失败不拖垮整批**：个别资源字段缺失/内容不合法时，该条
  `status="invalid"` 并携带可区分的错误（如 `resource_validation_failed` 及缺失字段），
  计入汇总 `invalid` 并拉低整批结论（`overall_action=deny`）——既不静默放行，
  也不影响其余合法资源照常出结论。
- **顺序无关**：汇总只依赖批次内容，同一批资源换序提交汇总一致
  （实际上会命中同一批次记录，见下文）。
- **规模**：上百条的批次在一次请求内顺序判定完毕，每条合法资源恰好产生
  一条判定记录，不重不漏。

## 重复上报的收口边界

调用方不带 `idempotency_key` 时，系统自动派生**内容幂等键**：

```
content:{policy_name}:{policy_version}:{policy_fingerprint}:{resource_fingerprint}
```

| 场景 | 是否算同一份 | 行为 |
|---|---|---|
| 同内容资源 + 同一策略版本，串行重试 | 是 | 复用首次判定，不产生新记录，返回 `idempotent_hit: true` |
| 同内容资源 + 同一策略版本，多进程/多线程同时交 | 是 | 锁内裁决，只有一条记录落盘，所有并发方拿到同一 `decision_id` |
| 资源内容有任何改动（指纹不同） | 否 | 视为新提交，产生新判定 |
| 策略发布了新版本（版本号/指纹变化） | 否 | 视为新提交，按新版本判定 |
| 显式指定旧版本重提同内容 | 是 | 复用该版本下的既有结论 |
| 携带显式 `idempotency_key` | 按键判定 | 维持既有语义：同键复用首次结论（首决确定性） |

**整批同理**：批次内容指纹 = 策略（名+版本+指纹）+ 排序后的逐条资源指纹。
同一批次重复提交（含换序）复用首次的 `batch_id` 与 `summary`，
返回 `idempotent_hit: true`；批次里只有一部分资源此前判过时，
这些条目复用旧结论（`reused: true`），其余正常新建——不重复、不漏判。
批次内容有任何一条变化、或策略版本变化，批次指纹即变化，视为新批次。

## 批次与策略版本的对应关系

- 策略在**批次开始时选定一次**（显式 `policy_version` 或当时最新版），
  整批落在同一策略快照上；批次执行期间发布新版本不影响本批，
  不会出现"半批旧版、半批新版"。
- 返回的 `policy.version` / `policy.fingerprint` 即本批实际使用的快照标识；
  每条判定记录同样固化版本与指纹，之后用
  `/api/decisions/{decision_id}/replay` 单独复现仍按该版本重算，结果稳定一致。

## 本地复现与验证

```bash
uv sync
uv run pytest -s tests/test_batch.py   # 批量与重复上报用例，日志含策略版本/指纹/判定依据
uv run pytest -s                      # 全量回归
```

手工验证（服务运行在 `uv run uvicorn main:app`）：

```bash
# 同一批次提交两次：第二次 idempotent_hit=true，batch_id 与 summary 与首次一致
curl -s -X POST localhost:8000/api/admit/batch -H 'content-type: application/json' \
  -d '{"resources": [...], "policy_name": "default"}' | jq '{batch_id, idempotent_hit, summary}'
```
