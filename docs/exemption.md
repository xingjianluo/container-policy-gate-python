# 豁免规则

## 1. 数据模型

```json
{
  "scope": {"kind": "Deployment", "namespace": "prod", "name": "web",
            "labels": {"app": "web"}},
  "rule_ids": ["image-fixed-tag"],
  "valid_from": "2026-09-23T09:00:00Z",
  "valid_until": "2026-09-23T11:00:00Z",
  "reason": "发布窗口",
  "idempotency_key": "可选的幂等键"
}
```

- **scope（生效范围）**：键与规则 `match` 相同
  （`kind`/`apiVersion`/`namespace`/`name`/`labels`）。
  资源必须落在范围内，豁免才可能被采纳；空对象表示对所有资源生效。
- **rule_ids**：限定豁免哪些规则；空数组表示豁免该资源命中的全部规则。
  规则不在列表中时，豁免对该规则不生效。
- **有效期**：闭区间 `[valid_from, valid_until]`，统一 ISO8601 UTC。
  判定时刻必须落在区间内；已过期或尚未生效的豁免一律不采纳。
- 时间倒置（`valid_from > valid_until`）的申请直接被拒绝
  （`policy_document_invalid`，响应 details 可区分）。

## 2. 状态机

```
requested ──approve──▶ approved ──revoke──▶ revoked
     │                    │
     └────reject────────▶ rejected
```

- `requested → approved / rejected`；`approved → revoked`；
- `rejected`、`revoked` 为终态；
- 任何非法流转（如 `requested → revoked`、重复 approve、
  revoked 后再 approve）都抛 `illegal_state_transition`（409），
  响应中给出 `from`、`to` 与 `allowed` 列表。

只有 **approved** 状态的豁免才参与准入判定；未批准、已驳回、
已撤销的豁免不会产生任何放行效果。

## 3. 采纳判定的优先级

一条豁免在准入时被采纳，当且仅当同时满足：

1. 状态为 `approved`；
2. 判定时刻在 `[valid_from, valid_until]` 内；
3. 资源命中其 `scope`；
4. 命中规则在 `rule_ids` 内（或 `rule_ids` 为空）。

采纳后，该规则的命中仍会如实记录为 `violation`，但 `exempted=true`，
处置从 `deny` 降级为 `allow_with_warning` —— 违规事实不被掩盖，
只是处置结果改变。

## 4. 可区分的拒绝原因

| 情形 | 错误码 | HTTP |
|---|---|---|
| 豁免不存在 | `exemption_not_found` | 404 |
| 已过期 / 尚未生效（显式采纳校验 `check_adoption`） | `exemption_expired` | 422 |
| 资源或规则不在生效范围内 | `exemption_out_of_scope` | 422 |
| 状态非法流转 | `illegal_state_transition` | 409 |

在准入判定主流程中，过期/越界的豁免采取“静默不采纳”策略
（但判定依据会写明“无有效豁免”）；需要对具体豁免做显式校验时，
可调用服务层 `ExemptionService.check_adoption(...)` 拿到可区分的错误码。

## 5. 幂等

豁免申请可携带 `idempotency_key`：同一键的重复提交返回**同一条**豁免，
不产生重复记录。并发提交由存储锁串行化，最终只有一条申请落盘。
