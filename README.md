# Local Policy Gateway（本地访问决策服务）

一个完全本地化运行的 Spring Boot 访问决策网关：用本地生成的 HMAC 密钥校验令牌，
用本地 JSON 策略按角色 / 资源 / 动作 / 环境属性做放行判定，支持密钥轮换过渡、
策略整版热更新与逐条审计，不依赖外部身份服务、真实凭据或付费组件。

## 快速开始

```bash
mvn -o clean package -DskipTests
java -jar target/local-policy-gateway-java-1.0-SNAPSHOT.jar
```

首次启动会自动生成 `local-keystore.json`（含首把 256 位随机签名密钥）并加载
`src/main/resources/policies/default-policy.json` 示例策略。

```bash
# 签发本地演示令牌
TOKEN=$(curl -s -X POST http://localhost:8080/admin/tokens/issue \
  -H 'Content-Type: application/json' \
  -d '{"subject":"alice","role":"reader","ttlMillis":3600000}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

# 做访问判定
curl -s -X POST http://localhost:8080/access -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOKEN\",\"resource\":\"docs\",\"action\":\"read\",\"env\":{\"env\":\"dev\"}}"
```

## 测试

```bash
mvn -o clean test
```

54 个单测覆盖放行、拒绝、密钥轮换、策略热更新等主线；测试日志末尾会按业务主线
打印各业务用例数与通过情况。

## 文档

- [架构说明（优先级与冲突规则、轮换过渡语义、防篡改、审计）](docs/architecture.md)
- [本地验证手册（构建 / curl 验证 / 测试说明）](docs/local-verification.md)

## 关键语义速览

- **默认拒绝**：无策略 `NO_POLICY_LOADED`、无命中 `NO_RULE_MATCHED`、命中 DENY
  `EXPLICIT_DENY`，令牌层另有 8 个可区分失败码。
- **多条命中的稳定优先级**：`priority` 大者胜 → 具体度（非通配维度 + env 约束数）
  高者胜 → 规则 ID 字典序；同范围同优先级效果相反在加载期判为 `CONTRADICTION`。
- **热更新原子性**：整版解析成功后一次引用发布；失败保留旧版，并发判定看不到半成品。
- **密钥轮换**：旧 ACTIVE 密钥在过渡期（默认 1 小时）内仍可验签，之后拒绝；可随时吊销。
- **防篡改**：密钥库带 SHA-256 校验和，篡改后拒绝加载（fail-closed）；
  令牌签名常量时间比较。
