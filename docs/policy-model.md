# 策略模型

## 1. 策略文档

策略是版本化、不可变的 JSON 文档，通过 `POST /api/policies` 发布。
每个策略以 `name` 标识，每次发布产生一个严格递增的整数 `version`
（首个版本为 1，必须连续，不允许跳号、回退或覆盖）。

```json
{
  "name": "default",
  "version": 1,
  "description": "可选描述",
  "rules": [ /* 规则数组，见下 */ ]
}
```

发布成功后返回该版本的 **内容指纹（fingerprint，sha256）**。
指纹覆盖原始文档与归一化后的规则，任何一处被篡改都会导致指纹不一致。
历史版本永不被修改或删除，判定记录通过 `策略名 + 版本号 + 指纹` 引用策略。

## 2. 规则

| 字段 | 必填 | 说明 |
|---|---|---|
| `id` | 是 | 策略内唯一的规则标识 |
| `field` | 是 | 被检查字段的点分路径，支持数字下标，如 `spec.containers.0.image` |
| `operator` | 是 | 判定算子（见下） |
| `value` | 视算子 | 算子右值；`present`/`absent` 可省略 |
| `match` | 否 | 资源选择器；空对象表示匹配所有资源 |
| `severity` | 否 | 严重级别：`low`/`medium`/`high`/`critical`，默认 `medium` |
| `on_violation` | 否 | 命中时的处置倾向：`deny`（默认）或 `warn` |
| `description` | 否 | 人类可读说明 |

### 选择器 match

支持键：`kind`、`apiVersion`、`namespace`、`name`、`labels`。
`labels` 为“标签子集”匹配（资源必须包含 selector 中给出的全部标签）。
不满足选择器的规则 **不参与判定**（区别于“参与但通过”）。

### 算子

| 算子 | 语义 | 右值要求 |
|---|---|---|
| `eq` / `ne` | 相等 / 不等 | 任意 JSON 值 |
| `in` / `not_in` | 值在/不在列表中 | 必须是数组 |
| `contains` / `not_contains` | 容器包含/不包含右值 | 任意 |
| `regex` | 正则搜索命中（`re.search`） | 必须是合法正则字符串 |
| `present` / `absent` | 字段存在 / 缺失 | 无右值 |
| `size_lte` / `size_gte` | 长度 ≤ / ≥ | 必须是整数 |

## 3. 结论：严重级别与处置结果分离

系统刻意区分两个维度：

- **severity（严重级别）**：规则本身的严厉程度，属于策略语义；
- **action（处置结果）**：对该资源清单的最终动作，属于准入结论。

最终 `action` 取值：

| action | 含义 | 触发条件 |
|---|---|---|
| `allow` | 放行 | 适用规则全部通过 |
| `allow_with_warning` | 放行但告警 | 命中的都是 `warn` 规则，或 `deny` 违规已被有效豁免 |
| `deny` | 拒绝 | 至少一条 `deny` 违规未被豁免 |

每条规则都产出一条命中依据 `RuleHit`：`rule_id`、`verdict`
（`pass`/`violation`）、`severity`、实际值 `actual`、期望值 `expected`、
是否被豁免 `exempted`、豁免 ID 以及人类可读的 `reason`。
判定结论 `rationale` 汇总未豁免违规数、最高严重级别与告警数，保证结论可解释。

## 4. 必须明确拒绝、绝不静默放行的情形

| 情形 | 错误码 `error` | HTTP |
|---|---|---|
| 策略 JSON 无法解析、结构/字段非法、规则 id 重复、枚举值非法 | `policy_document_invalid` | 422 |
| 文档结构合法，但算子未知/右值类型错/正则非法/字段路径语法不支持 | `unsupported_rule_syntax` | 422 |
| 资源清单缺 `apiVersion`/`kind`/`metadata`/`spec`、`metadata.name` 为空等 | `resource_validation_failed` | 422 |
| 策略版本号重复/不连续、历史内容指纹不符 | `policy_version_conflict` | 409 |
| 引用的策略不存在 | `policy_document_invalid` | 422 |

畸形策略发布失败时不会产生任何“零规则版本”，因此不会出现
“策略坏了 → 没有规则匹配 → 全部放行”的静默失效。
