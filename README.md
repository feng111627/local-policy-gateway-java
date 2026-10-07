# Local Policy Gateway（本地访问决策服务）

一个**只依赖本地资源**的 Spring Boot 访问决策服务：用本地策略配置判定一个请求是否放行，
鉴权令牌使用**进程内本地生成的 HMAC 密钥**签名与校验，全程不连接任何外部服务、不需要真实凭据、
不使用任何付费组件。

- 默认拒绝：没有任何规则匹配时一律 DENY。
- 判定可解释：结果里带命中规则 id、策略版本和“为什么放行/拒绝”。
- 错误不静默：策略缺字段、语法错误、规则矛盾、令牌过期/被吊销/签名不符/密钥未知/密钥被篡改，
  都有**可区分**的拒绝原因。
- 热更新原子化：策略更新要么整体生效、要么整体不生效；并发判定看不到半成品；失败保留上一版。
- 密钥可轮换：轮换过渡期内旧密钥令牌仍可用。
- 每次判定都写一条可追溯审计记录。

---

## 1. 快速开始

需要 JDK 17+（工程基于 Spring Boot 3.4）。

```bash
mvn spring-boot:run
```

服务默认监听 `http://localhost:8080`，启动时加载内置策略
`src/main/resources/policies/default-policy.json`，并在内存中随机生成第一把签名密钥。

本地验证一条龙（见第 6 节完整脚本）：

```bash
# 1) 用本地 ACTIVE 密钥签发一个 admin 令牌
TOKEN=$(curl -s -X POST http://localhost:8080/local-gateway/tokens \
  -H 'Content-Type: application/json' \
  -d '{"sub":"alice","roles":["admin"],"ttlSeconds":3600}' | sed 's/.*"token":"\([^"]*\)".*/\1/')

# 2) 带令牌做访问判定
curl -s -X POST http://localhost:8080/local-gateway/decide \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"resource":"docs/readme","env":{"env":"prod"}}'
```

---

## 2. 策略模型

策略是一份 JSON（见 `policies/default-policy.json`）：

```json
{
  "policyId": "default-local-policy",
  "name": "内置默认本地策略",
  "version": 1,
  "rules": [
    {
      "id": "allow-admin-docs-prod",
      "effect": "ALLOW",
      "priority": 200,
      "roles": ["admin"],
      "resources": ["docs/*"],
      "env": {"env": ["prod", "staging"]}
    }
  ]
}
```

| 字段 | 含义 | 缺省语义 |
| --- | --- | --- |
| `policyId` / `name` / `version` | 策略标识、名称、**单调递增版本号** | 前两个必填；version 必须为正整数且更新时必须大于当前版本 |
| `rules[].id` | 规则唯一标识，用于审计与解释 | 必填，重复会被拒绝（`DUPLICATE_RULE_ID`） |
| `effect` | `ALLOW` 或 `DENY` | 必填，其他取值报 `INVALID_VALUE` |
| `priority` | 优先级，**数值越大越优先** | 不能为负数 |
| `roles` | 命中所需角色（任一匹配） | `null`/缺省 = 不限制角色 |
| `resources` | 资源匹配：精确匹配，或末尾单段通配 `docs/*` | `null`/缺省 = 不限制资源 |
| `env` | 环境约束：键必须存在，请求值须落在候选值列表中 | `null`/缺省 = 不限制环境 |

资源通配规则：`docs/*` 匹配 `docs/readme`，但**不跨路径段**（不匹配 `docs/a/b`）；
单独的 `*` 匹配任意资源。

### 2.1 优先级与冲突处理规则（稳定且可解释）

判定按下列确定性步骤进行，结果可复现：

1. **匹配筛选**：用令牌角色 + 请求资源 + 环境属性筛出所有匹配规则。一条都没有
   → **默认拒绝**，原因 `NO_MATCHING_RULE`。
2. **只看最高优先级层**：匹配规则按 `priority` 降序，仅在**最高**优先级那一层决策，
   低层规则无论 allow/deny 都不再影响结果。
3. **最高层一致 → 采纳**：层内全部 ALLOW 则放行；全部 DENY 则拒绝（`EXPLICITLY_DENIED`）。
   命中规则取层内 **id 字典序第一条**写入响应，保证多次判定命中来源稳定。
4. **最高层矛盾 → 拒绝且不静默**：同一最高优先级层内同时出现 ALLOW 与 DENY
   → 返回 `CONTRADICTORY_RULES` 拒绝。

   - **装载期静态矛盾**：热更新/启动校验时，若同优先级两条规则的匹配域静态可重叠
     （角色/资源/环境存在同时满足的可能）且效果相反，整份策略被拒绝，错误码
     `CONTRADICTORY_RULES`，不会上线。
   - **运行期动态矛盾**：个别因通配/多维环境造成静态不可判定、运行时才同时命中的情况，
     引擎在最高层检测到 ALLOW+DENY 仍返回 `CONTRADICTORY_RULES`，绝不在冲突时偷偷放行。

### 2.2 策略错误码（热更新失败可区分）

| 错误码 | 触发情形 |
| --- | --- |
| `SYNTAX_ERROR` | JSON 词法/语法错误，无法解析 |
| `MISSING_FIELD` | 缺 policyId、缺 rules、规则缺 id 等必填字段 |
| `INVALID_VALUE` | effect 非 ALLOW/DENY、优先级为负、字段类型错误、env 候选值为空等 |
| `DUPLICATE_RULE_ID` | 规则 id 重复 |
| `CONTRADICTORY_RULES` | 同优先级存在静态可重叠且效果相反的规则 |
| `STALE_VERSION` | 新版本号不大于当前生效版本 |

任何一种失败都会让更新**整体不生效**，响应里同时给出仍在生效的旧版本号。

---

## 3. 本地令牌与密钥轮换

### 3.1 令牌格式

紧凑三段式，仅用 JDK 的 Base64URL 与 HMAC-SHA256，无外部 IdP：

```
base64url(header) . base64url(claims) . base64url(HMAC-SHA256(secret, header + "." + claims))
```

- `header = {"kid": "<签名密钥id>", "ver": "LPG1"}`
- `claims = {"sub": "主体", "roles": ["..."], "iat": <签发秒>, "exp": <过期秒>}`

通过 `POST /local-gateway/tokens` 可用当前 ACTIVE 密钥签发本地测试令牌。

### 3.2 密钥状态与轮换过渡语义

密钥库中的每把密钥处于三种状态之一：

| 状态 | 能否签发 | 能否校验 | 说明 |
| --- | --- | --- | --- |
| `ACTIVE` | 是 | 是 | 当前密钥，全库仅一把 |
| `PREVIOUS` | 否 | **是** | 上一代密钥，**轮换过渡期**内旧令牌仍可校验 |
| `REVOKED` | 否 | 否 | 已吊销，命中即拒绝 |

`POST /local-gateway/admin/keys/rotate` 的语义：

1. 随机生成新密钥并置为 ACTIVE（之后签发的令牌用新 `kid`）；
2. 原 ACTIVE 降级为 `PREVIOUS` —— **过渡期内它签发的旧令牌依旧可通过校验**；
3. 更早的那把 `PREVIOUS` 变为 `REVOKED`（过渡期只保留一代旧密钥）；
4. 响应返回 `activeKid` 与过渡期 `previousKid`。

也可用 `revoke` 语义手动吊销（`KeyStore#revoke`），吊销后该密钥令牌立即失效。

### 3.3 拒绝原因（令牌阶段全部可区分）

| DenyReason | 含义 |
| --- | --- |
| `NO_TOKEN` | 请求未携带令牌 |
| `MALFORMED_TOKEN` | 非三段式 / Base64 或 JSON 无法解析 / 头部缺 kid |
| `SIGNATURE_MISMATCH` | 签名与本地密钥不一致（令牌被篡改） |
| `UNKNOWN_KEY` | 令牌 `kid` 在本地密钥库中不存在 |
| `TOKEN_EXPIRED` | `exp` 已过 |
| `KEY_REVOKED` | 签发密钥已被吊销 |
| `KEY_TAMPERED` | 本地密钥材料完整性指纹不匹配（密钥被篡改） |
| `NO_MATCHING_RULE` / `EXPLICITLY_DENIED` / `CONTRADICTORY_RULES` | 策略阶段拒绝 |

### 3.4 防篡改

每把密钥在入库时附带完整性指纹（对 `kid|secret|state` 用进程内 pepper 计算的
HMAC-SHA256）。校验令牌前先校验密钥指纹：若有人直接改了密钥材料或状态、却无法用拿不到的
pepper 重算指纹，判定直接返回 `KEY_TAMPERED`，被篡改的密钥或令牌**不会**被当作合法请求放行。
签名比对与指纹比对均使用恒定时间比较（`MessageDigest.isEqual`）。

---

## 4. 热更新与并发安全

- 生效策略保存在 `AtomicReference<Policy>` 中，Policy 及其规则列表均为不可变对象；
  “整体生效”通过**单次引用赋值**完成。
- 判定服务在令牌校验通过后抓取**一次**策略快照，引擎对该快照求值，响应版本号与审计记录都来自
  同一快照——并发更新期间，任何一次判定要么完全基于旧版、要么完全基于新版，不可能看到半成品。
- 更新流程为 **解析 → 校验 → 原子替换**；前两步抛错时根本不会触碰当前引用，因此失败时
  上一版策略完整保留。
- 每次判定（含无令牌、坏令牌等拒绝）都向内存审计日志追加一条 `AuditEvent`
  （时间、主体、资源、决策、拒绝原因、命中规则、策略 id/版本、kid、明细），
  通过 `GET /local-gateway/admin/audit` 查看。

---

## 5. HTTP 接口

| 方法与路径 | 说明 |
| --- | --- |
| `POST /local-gateway/tokens` | 本地签发令牌：`{"sub","roles","ttlSeconds"}`，返回 `{token, kid}` |
| `POST /local-gateway/decide` | 访问判定，Header `Authorization: Bearer <token>`，Body `{"resource","env"}`；放行 200，拒绝 403 |
| `POST /local-gateway/admin/policies/reload` | 热更新：`{"json": "<策略文本>"}`（也接受 `policy` 字段） |
| `POST /local-gateway/admin/keys/rotate` | 密钥轮换，返回 `{success, activeKid, previousKid, message}` |
| `GET /local-gateway/admin/audit` | 查看审计记录 |

判定响应示例（拒绝时 HTTP 403）：

```json
{
  "decision": "DENY",
  "reason": "[EXPLICITLY_DENIED] 命中规则 deny-prod-write-by-default（优先级 100，最高优先级层一致 DENY），拒绝",
  "matchedRuleId": "deny-prod-write-by-default",
  "policyId": "default-local-policy",
  "policyVersion": 1,
  "subject": "viewer-user"
}
```

---

## 6. 本地验证方法

### 6.1 运行测试并查看业务覆盖汇总

```bash
mvn test
```

日志末尾会打印各业务主线的用例数与通过情况，例如：

```
[测试覆盖汇总] 主线一：策略访问判定（放行/拒绝/优先级/默认拒绝）  用例  8 | 通过  8 | 失败 0 | 跳过 0
[测试覆盖汇总] 主线二：本地密钥轮换与令牌校验                    用例 10 | 通过 10 | 失败 0 | 跳过 0
[测试覆盖汇总] 主线三：策略热更新（原子生效/失败保留/并发一致/审计） 用例  8 | 通过  8 | 失败 0 | 跳过 0
[测试覆盖汇总] 主线四：HTTP 端到端（状态码/解释字段/管理端点）     用例  5 | 通过  5 | 失败 0 | 跳过 0
[测试覆盖汇总] 冒烟：Spring 上下文装配与默认策略启动              用例  1 | 通过  1 | 失败 0 | 跳过 0
[测试覆盖汇总] 合计：业务 5 项，用例 32，通过 32，失败 0，跳过 0
```

覆盖主线：放行、默认/显式拒绝、优先级、动态矛盾；轮换过渡期、二次轮换吊销、过期、签名篡改、
未知密钥、密钥材料篡改；热更新整体生效、各类非法策略失败保留旧版、版本回退、并发一致性、审计。

### 6.2 运行起来手动验证

```bash
mvn spring-boot:run
```

放行（admin + prod）：

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/local-gateway/tokens \
  -H 'Content-Type: application/json' \
  -d '{"sub":"alice","roles":["admin"],"ttlSeconds":3600}' | sed 's/.*"token":"\([^"]*\)".*/\1/')

curl -s -X POST http://localhost:8080/local-gateway/decide \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"resource":"docs/readme","env":{"env":"prod"}}'
# decision=ALLOW, matchedRuleId=allow-admin-docs-prod
```

拒绝（viewer + prod 命中显式 DENY）：

```bash
VT=$(curl -s -X POST http://localhost:8080/local-gateway/tokens \
  -H 'Content-Type: application/json' \
  -d '{"sub":"bob","roles":["viewer"],"ttlSeconds":3600}' | sed 's/.*"token":"\([^"]*\)".*/\1/')

curl -s -i -X POST http://localhost:8080/local-gateway/decide \
  -H "Authorization: Bearer $VT" -H 'Content-Type: application/json' \
  -d '{"resource":"docs/readme","env":{"env":"prod"}}'
# HTTP/1.1 403, decision=DENY, reason=[EXPLICITLY_DENIED] ...
```

无令牌（`NO_TOKEN`）：

```bash
curl -s -i -X POST http://localhost:8080/local-gateway/decide \
  -H 'Content-Type: application/json' -d '{"resource":"docs/readme","env":{"env":"prod"}}'
```

密钥轮换：旧令牌在过渡期内仍然可用，再轮换一次后第一代密钥被吊销：

```bash
curl -s -X POST http://localhost:8080/local-gateway/admin/keys/rotate
curl -s -X POST http://localhost:8080/local-gateway/decide \
  -H "Authorization: Bearer $VT" -H 'Content-Type: application/json' \
  -d '{"resource":"docs/readme","env":{"env":"dev"}}'   # 旧 PREVIOUS 密钥令牌仍通过
curl -s -X POST http://localhost:8080/local-gateway/admin/keys/rotate
curl -s -i -X POST http://localhost:8080/local-gateway/decide \
  -H "Authorization: Bearer $VT" -H 'Content-Type: application/json' \
  -d '{"resource":"docs/readme","env":{"env":"dev"}}'   # 403, reason=[KEY_REVOKED]
```

热更新失败保留旧版（故意给语法错误）：

```bash
curl -s -X POST http://localhost:8080/local-gateway/admin/policies/reload \
  -H 'Content-Type: application/json' -d '{"json":"{ broken json"}'
# {"success":false,"activeVersion":1,"errorCode":"SYNTAX_ERROR", ...}
```

查看审计：

```bash
curl -s http://localhost:8080/local-gateway/admin/audit
```

---

## 7. 代码结构

```
model/    Decision / DenyReason / Policy / Rule / TokenClaims / StoredKey 等类型
policy/   PolicyParser、PolicyValidator、PolicyRepository、PolicyEngine
token/    KeyStore、LocalTokenService 及令牌/密钥完整性异常
audit/    AuditEvent、AuditLog
service/  GatewayService（令牌校验 → 策略判定 → 审计 的总编排）
web/      GatewayController
config/   Clock Bean、启动时默认策略装载
```
