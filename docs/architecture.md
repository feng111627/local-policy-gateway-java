# 本地访问决策服务 — 架构说明

## 1. 设计目标

在**不依赖任何外部服务、真实凭据或付费组件**的前提下，提供一个可独立运行的本地访问
决策网关：

- 用**本地生成、本地保存**的 HMAC 密钥签发/校验令牌；
- 用**本地 JSON 策略**按“角色 + 资源 + 动作 + 环境属性”判定放行/拒绝；
- 默认拒绝；命中多条规则时按**稳定且可解释**的优先级裁决；
- 策略支持运行期**整版热更新**，更新失败保留上一版；
- 每次判定都写一条**可追溯审计记录**；
- 被篡改的令牌或密钥库**绝不可能**被当成合法请求放行。

全部能力只使用 JDK 内置加密原语（HMAC-SHA256、SHA-256、SecureRandom）与 Spring Boot
自带的 Jackson，离线可构建、可运行、可测试。

## 2. 模块结构

```
policy/   策略模型、解析校验、裁决引擎、热更新服务
auth/     本地密钥库（完整性保护）、HMAC 令牌签发/校验
audit/    审计记录与审计服务
gateway/  编排：令牌校验 -> 策略裁决 -> 审计留痕
web/      /access 判定端点、/admin 管理端点、统一错误翻译
config/   Bean 装配、启动引导、配置属性
```

一次请求的处理链路：

```
POST /access
  -> AccessController          入参校验
  -> GatewayService.decide
       -> TokenService.verify  本地 HMAC 校验（失败即拒绝，原因可区分）
       -> PolicyEngine.evaluate 角色/资源/动作/环境匹配 + 稳定优先级裁决
       -> AuditService.record  无论放行/拒绝都追加审计
  -> AccessResponse { permitted, reasonCode, matchedRuleId, policyVersion, requestId }
```

## 3. 策略模型

策略是一版完整 JSON，整体生效或整体不生效：

```json
{
  "version": "default-v1",
  "rules": [
    {
      "id": "reader-read-docs-prod-deny",
      "effect": "DENY",
      "priority": 20,
      "role": "reader",
      "resource": "docs",
      "action": "read",
      "env": { "env": "prod" }
    }
  ]
}
```

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `id` | 是 | 规则唯一 ID，重复会拒绝整版加载 |
| `effect` | 是 | `PERMIT` 或 `DENY`，其它取值拒绝加载 |
| `priority` | 否（默认 0） | 整数，数值越大优先级越高 |
| `role` | 是 | 精确值或 `*` |
| `resource` | 是 | 精确值或 `*` |
| `action` | 否（默认 `*`） | 精确值或 `*` |
| `env` | 否（默认空） | 环境属性的等值约束集合，必须全部满足 |

匹配规则：`role/resource/action` 支持精确值或 `*` 通配；`env` 中的**每一个**
等值约束都必须在请求环境里满足（AND 语义，不支持取反与通配，避免隐式放宽）。

## 4. 优先级与冲突规则（核心语义）

多条规则同时命中一个请求时，按下面的**确定性顺序**选出唯一“胜出规则”，
由它的 `effect` 决定结果；结果里的 `matchedRuleId` 与 `message` 会说明胜出者及胜出理由。

1. **优先级**：`priority` 数值大的规则胜出，与规则在文件中的声明顺序无关。
2. **具体度**：优先级相同时，匹配更“具体”的规则胜出。具体度计分：
   `role/resource/action` 中每个非 `*` 维度计 1 分，`env` 中每条约束计 1 分；总分高者胜。
3. **规则 ID**：优先级与具体度都相同时，按 `id` 字典序决定，保证结果完全确定、可复现。

**矛盾（冲突）的处理是显式失败，而不是静默选一条：**

- 若两条规则的匹配范围完全相同（`role/resource/action/env` 全等）、
  `priority` 相同，但 `effect` 相反，则它们在该请求上的结果是歧义的。
  解析阶段直接以 `CONTRADICTION` 拒绝**整版**策略加载，旧版策略继续生效，
  歧义规则永远不会进入运行期裁决。
- 若匹配范围相同但 `priority` 不同，效果相反**不算矛盾**——优先级本来就是用来解决
  这种冲突的，高优先级稳定胜出。

**默认拒绝**体现在三个可区分层面：

- 当前没有任何已生效策略：`NO_POLICY_LOADED`；
- 有策略但没有任何规则匹配：`NO_RULE_MATCHED`；
- 有规则命中但胜出规则是 `DENY`：`EXPLICIT_DENY`。

策略加载失败同样可区分，绝不静默跳过：

| 原因码 | 触发条件 |
| --- | --- |
| `SYNTAX_ERROR` | JSON 无法解析、根节点不是对象 |
| `MISSING_FIELD` | 缺 `rules`，或规则缺 `id/effect/role/resource` 等必填字段 |
| `INVALID_VALUE` | `effect` 非法、`priority` 非整数、`env` 不是对象等 |
| `DUPLICATE_RULE_ID` | 两条规则 ID 相同 |
| `CONTRADICTION` | 同范围、同优先级、效果相反 |

## 5. 策略热更新的原子语义

`PolicyAdminService.apply(json)` 的事务流程：

1. 在调用栈局部用 `PolicyParser` 完整解析、校验、做矛盾检测；
2. 解析成功后调用 `PolicyEngine.replace`，这只是对 `AtomicReference<Policy>`
   的一次引用发布（volatile 语义）；
3. 解析任何阶段抛异常，都直接返回失败结果，**当前生效版本原封不动**。

因此并发判定线程要么看到旧版全部规则，要么看到新版全部规则，
不可能观察到“只更新一半”的混合策略。测试 `PolicyHotReloadTest` 用 8 线程 × 500 次
判定与热更新并发执行，断言每次结果只能完整来自旧版或新版。

## 6. 本地签名密钥与令牌

### 6.1 令牌格式

JWT 风格的紧凑三段式 base64url（无 JWT 库依赖）：

```
base64url(header).base64url(payload).base64url(signature)
header    = {"alg":"HS256","kid":"<密钥ID>"}
payload   = {"iss":"local-policy-gateway","sub","role","iat","nbf","exp"}
signature = HMAC-SHA256(header.payload, kid 对应密钥)
```

签名比较使用 `MessageDigest.isEqual`（常量时间），避免计时侧信道。

### 6.2 校验失败的可区分原因

验签顺序固定，使每类失败都有独立原因码：

| 原因码 | 含义 |
| --- | --- |
| `MALFORMED_TOKEN` | 不是三段式、base64url/JSON 损坏、缺必填声明、签发者不符 |
| `UNKNOWN_KEY` | `kid` 在本地密钥库中不存在（伪造的或来自其他系统） |
| `KEY_REVOKED` | `kid` 存在但已被显式吊销 |
| `KEY_TRANSITION_EXPIRED` | `kid` 是旧密钥，轮换过渡期已结束 |
| `BAD_SIGNATURE` | 密钥有效但签名不符（令牌内容被篡改） |
| `TOKEN_EXPIRED` | 当前时间超过 `exp` |
| `TOKEN_NOT_YET_VALID` | 当前时间早于 `nbf` |
| `KEYSTORE_TAMPERED` | 密钥库校验和不匹配 / 结构非法 / ACTIVE 数量不为 1 |

### 6.3 密钥轮换的过渡语义

每把密钥处于三种状态之一：

- `ACTIVE`：当前主用密钥，新令牌用它签发，始终可验签；
- `RETIRED`：被轮换下去的旧密钥，**仅在过渡期内**仍可验签，
  过渡期截止时刻 = 轮换发生时刻 + `gateway.rotation-overlap-millis`（默认 1 小时）；
- `REVOKED`：被显式吊销，任何时候都不可验签。

`POST /admin/keys/rotate` 的效果是原子的：旧 `ACTIVE` 置为 `RETIRED` 并写入过渡期截止
时刻，同时生成新的 `ACTIVE`。于是：

- 轮换发生前已签发的令牌，在过渡期内**继续可用**，业务无中断；
- 过渡期结束后，旧令牌以 `KEY_TRANSITION_EXPIRED` 被拒绝；
- 过渡期内若旧密钥被吊销，则以 `KEY_REVOKED` 拒绝（吊销优先于过渡过期）；
- 新签发的令牌一律使用新密钥。

### 6.4 密钥库防篡改

密钥库文件 `local-keystore.json`（路径由 `gateway.key-store-file` 指定）形如：

```json
{
  "version": 1,
  "checksum": "<base64(sha256(规范化后的 keys 数组 JSON))>",
  "keys": [ {"kid","algorithm","secret(base64)","state","createdAt","retireAt"} ]
}
```

- 任何对 `keys` 内容的手工改动（改 secret、改 state、增删条目）都会使 `checksum`
  不匹配，加载立刻以 `KEYSTORE_TAMPERED` 失败，应用**拒绝启动**（fail-closed）；
- 写盘采用“临时文件 + 原子 move”，避免落盘半成品；
- 首次启动文件不存在时自动引导生成一把 256 位随机密钥。

> 说明：校验和用于检测意外/手工篡改，属于演示级完整性保护；
> 它不替代真实环境中的 KMS、文件权限与 HSM 等纵深防御。

## 7. 审计

每次进入判定链路的请求都会追加一条 `AuditRecord`（SLF4J 的 `AUDIT` logger
结构化输出，并在内存保留最近 1 万条），字段包括：

`timestamp, requestId, subject, role, resource, action, outcome(PERMIT/DENY/TOKEN_INVALID),
reasonCode, matchedRuleId, policyVersion, kid`。

坏令牌在令牌层就被拒绝时也会留痕（`outcome=TOKEN_INVALID`，原因码即上表中的
令牌/密钥失败码），便于事后区分“为什么没放行”。

## 8. HTTP 接口

| 方法与路径 | 作用 |
| --- | --- |
| `POST /access` | 提交 `{token, resource, action, env}` 做访问判定；HTTP 200 表示判定完成，结论看 `permitted` |
| `POST /admin/policies` | 请求体为完整策略 JSON，整版热更新；返回 `{applied, version, reason, detail}` |
| `POST /admin/keys/rotate` | 密钥轮换，返回新旧 `kid` 与过渡期时长 |
| `POST /admin/keys/revoke` | 请求体为 kid 字符串，吊销指定密钥 |
| `POST /admin/tokens/issue` | **仅本地演示用**：用当前 ACTIVE 密钥签发令牌 |

HTTP 层对“请求本身非法/令牌字段缺失”返回 401/400 与统一错误体
`{error, reason, requestId}`；对“能进入判定但结论为拒绝”的请求返回 200，
拒绝原因放在 `reasonCode`，两类语义不混淆。

> 管理端点没有引入任何外部鉴权组件；本服务定位为本地/内网演示，真实部署应在其前置
> 网关或网络层加访问控制。
