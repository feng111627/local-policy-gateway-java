# 本地验证手册

全部操作均在离线环境完成，不需要任何外部账号、真实凭据或付费组件。

## 1. 环境要求

- JDK 17+（开发环境实测 JDK 25）
- Maven 3.6+（依赖可在本地仓库离线解析）

## 2. 构建与运行

```bash
# 离线构建（跳过测试打可执行 jar）
mvn -o clean package -DskipTests

# 启动（首次启动自动在工程根目录生成 local-keystore.json 并引导首把密钥）
java -jar target/local-policy-gateway-java-1.0-SNAPSHOT.jar
```

启动日志关键行：

```
本地密钥库已加载: ./local-keystore.json (ACTIVE=k-..., 总密钥数=1)
策略热更新整体生效: <none> -> default-v1
启动加载策略成功: default-v1
```

不启动服务也可以验证逻辑：所有主线路径都由单元测试覆盖（见第 4 节）。

## 3. 用 curl 验证业务主线

以下命令假设服务监听 `http://localhost:8080`。

### 3.1 签发本地令牌

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/admin/tokens/issue \
  -H 'Content-Type: application/json' \
  -d '{"subject":"alice","role":"reader","ttlMillis":3600000}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
```

### 3.2 放行 / 环境拒绝 / 默认拒绝

```bash
# 放行：reader 读 docs（dev 环境）
curl -s -X POST http://localhost:8080/access -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOKEN\",\"resource\":\"docs\",\"action\":\"read\",\"env\":{\"env\":\"dev\"}}"
# {"permitted":true,"reasonCode":"PERMIT","matchedRuleId":"reader-read-docs",...}

# 显式拒绝：prod 环境命中更具体的 DENY 规则
curl -s -X POST http://localhost:8080/access -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOKEN\",\"resource\":\"docs\",\"action\":\"read\",\"env\":{\"env\":\"prod\"}}"
# {"permitted":false,"reasonCode":"EXPLICIT_DENY","matchedRuleId":"reader-read-docs-prod-deny",...}

# 默认拒绝：没有任何规则匹配
curl -s -X POST http://localhost:8080/access -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOKEN\",\"resource\":\"payments\",\"action\":\"read\"}"
# {"permitted":false,"reasonCode":"NO_RULE_MATCHED","matchedRuleId":null,...}
```

### 3.3 各类坏令牌的可区分拒绝

```bash
# 篡改/损坏令牌
curl -s -X POST http://localhost:8080/access -H 'Content-Type: application/json' \
  -d "{\"token\":\"${TOKEN}xx\",\"resource\":\"docs\",\"action\":\"read\"}"
# {"permitted":false,"reasonCode":"MALFORMED_TOKEN",...}

# 缺少 token（HTTP 401）
curl -i -s -X POST http://localhost:8080/access -H 'Content-Type: application/json' \
  -d '{"resource":"docs","action":"read"}'
# {"error":"TOKEN_VERIFICATION_FAILED","reason":"MALFORMED_TOKEN",...}
```

其它原因（`UNKNOWN_KEY / KEY_REVOKED / BAD_SIGNATURE / TOKEN_EXPIRED /
TOKEN_NOT_YET_VALID / KEY_TRANSITION_EXPIRED`）在单测中逐一覆盖，
见 `TokenServiceTest`。

### 3.4 密钥轮换：过渡期内旧令牌仍可用

```bash
OLD_TOKEN=$TOKEN   # 轮换前签发的令牌
curl -s -X POST http://localhost:8080/admin/keys/rotate
# {"newKid":"k-...","previousKid":"k-...","status":"ROTATED: 旧密钥 ... 在 3600000ms 过渡期内仍可验签"}

# 旧令牌在过渡期内依然放行
curl -s -X POST http://localhost:8080/access -H 'Content-Type: application/json' \
  -d "{\"token\":\"$OLD_TOKEN\",\"resource\":\"docs\",\"action\":\"read\"}"
# {"permitted":true,...}
```

把 `gateway.rotation-overlap-millis` 调小（例如 1000）再轮换，1 秒后旧令牌即被拒，
原因码为 `KEY_TRANSITION_EXPIRED`。

### 3.5 策略热更新：整体生效 / 失败保留旧版

```bash
# 非法策略（规则缺 effect）-> 整体不生效，返回可区分原因，旧版保留
curl -s -X POST http://localhost:8080/admin/policies \
  -H 'Content-Type: application/json' \
  -d '{"version":"bad","rules":[{"id":"x","role":"reader","resource":"docs"}]}'
# {"applied":false,"version":"default-v1","reason":"MISSING_FIELD",...}

# 合法新策略 -> 整版生效
curl -s -X POST http://localhost:8080/admin/policies \
  -H 'Content-Type: application/json' \
  -d '{"version":"v2","rules":[{"id":"d","effect":"DENY","role":"reader","resource":"*","action":"*"}]}'
# {"applied":true,"version":"v2",...}
```

### 3.6 审计留痕

每次判定都在服务端日志输出 `AUDIT` 行，例如：

```
AUDIT requestId=... subject=alice role=reader resource=docs action=read
      outcome=PERMIT reason=PERMIT rule=reader-read-docs
      policyVersion=default-v1 kid=k-...
```

### 3.7 密钥库防篡改

```bash
# 服务停止后，手工修改 local-keystore.json 中任意密钥的 state/secret
python3 - <<'PY'
import json
p='local-keystore.json'
d=json.load(open(p))
for k in d['keys']:
    if k['state']=='ACTIVE': k['state']='RETIRED'
json.dump(d, open(p,'w'))
PY

# 再启动：应用拒绝启动（fail-closed），日志给出明确原因
java -jar target/local-policy-gateway-java-1.0-SNAPSHOT.jar
# -> 密钥库校验和不匹配，文件已被篡改: ./local-keystore.json
# 恢复方式：删除该文件，重启后会重新引导新密钥（旧令牌随之全部失效）
```

## 4. 运行单元测试

```bash
mvn -o clean test
```

测试结束时控制台会打印“业务覆盖与用例通过情况”汇总，按业务主线列出用例数与通过情况：

```
================ 业务覆盖与用例通过情况 ================
[测试覆盖] 放行主线                                    : 3/3 通过 全部通过
[测试覆盖] 拒绝主线(默认拒绝/显式拒绝/环境属性)              : 4/4 通过 全部通过
[测试覆盖] 优先级与冲突处理                              : 4/4 通过 全部通过
[测试覆盖] 策略加载失败可区分(缺字段/语法/矛盾)              : 8/8 通过 全部通过
[测试覆盖] 令牌正常校验                                  : 1/1 通过 全部通过
[测试覆盖] 令牌拒绝原因可区分(过期/吊销/签名/未知密钥)        : 6/6 通过 全部通过
[测试覆盖] 密钥轮换过渡语义                              : 3/3 通过 全部通过
[测试覆盖] 本地密钥库(引导/轮换/吊销/防篡改)                : 7/7 通过 全部通过
[测试覆盖] 策略热更新(整体生效/失败保留/并发一致)            : 5/5 通过 全部通过
[测试覆盖] 端到端编排与审计留痕                           : 5/5 通过 全部通过
[测试覆盖] HTTP 端到端(放行/拒绝/坏令牌/热更新/轮换)       : 7/7 通过 全部通过
[测试覆盖] Spring 上下文启动                            : 1/1 通过 全部通过
[测试覆盖] 合计: 54/54 通过
```

| 测试类 | 覆盖主线 |
| --- | --- |
| `PolicyParserTest` | 语法错误、缺字段、非法值、重复 ID、矛盾规则均可区分拒绝 |
| `PolicyEngineTest` | 放行、默认拒绝、显式拒绝、环境属性、优先级/具体度/ID 三级决胜 |
| `TokenServiceTest` | 正常校验；坏格式/未知 kid/吊销/过期/nbf/坏签名/过渡过期；轮换语义 |
| `KeyStoreTest` | 首次引导、轮换与过渡窗口、吊销、落盘重载、篡改 state/checksum 检测 |
| `PolicyHotReloadTest` | 整版生效、各类失败保留旧版、8 线程并发判定只见完整版本 |
| `GatewayServiceTest` | 编排与审计：放行、拒绝、坏令牌、过期、轮换+热更新联动 |
| `WebEndToEndTest` | 真实 Spring MVC 链路的 HTTP 行为 |

## 5. 配置项（`src/main/resources/application.properties`）

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `gateway.policy-file` | `src/main/resources/policies/default-policy.json` | 启动加载与热更新持久化的策略文件 |
| `gateway.key-store-file` | `./local-keystore.json` | 受完整性保护的本地密钥库 |
| `gateway.rotation-overlap-millis` | `3600000` | 密钥轮换过渡期长度 |
| `server.port` | `8080` | 监听端口 |
