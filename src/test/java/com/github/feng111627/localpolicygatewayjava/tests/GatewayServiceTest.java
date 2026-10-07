package com.github.feng111627.localpolicygatewayjava.tests;

import com.github.feng111627.localpolicygatewayjava.audit.AuditOutcome;
import com.github.feng111627.localpolicygatewayjava.audit.AuditRecord;
import com.github.feng111627.localpolicygatewayjava.audit.AuditService;
import com.github.feng111627.localpolicygatewayjava.auth.KeyStore;
import com.github.feng111627.localpolicygatewayjava.auth.TokenService;
import com.github.feng111627.localpolicygatewayjava.gateway.AccessResponse;
import com.github.feng111627.localpolicygatewayjava.gateway.GatewayService;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyAdminService;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyEngine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 端到端主线：令牌校验 -> 策略判定 -> 审计留痕，含轮换与热更新联动。 */
class GatewayServiceTest {

    @TempDir
    Path dir;

    private KeyStore keyStore;
    private TokenService tokens;
    private PolicyEngine engine;
    private PolicyAdminService admin;
    private AuditService audit;
    private GatewayService gateway;

    @BeforeEach
    void setUp() {
        keyStore = new KeyStore(dir.resolve("keystore.json"));
        keyStore.load();
        tokens = new TokenService(keyStore);
        engine = new PolicyEngine();
        admin = new PolicyAdminService(engine);
        audit = new AuditService();
        gateway = new GatewayService(tokens, keyStore, engine, audit);

        admin.apply("""
                {"version":"v1","rules":[
                  {"id":"reader-read","effect":"PERMIT","priority":10,
                   "role":"reader","resource":"docs","action":"read"},
                  {"id":"deny-all-write","effect":"DENY","priority":50,
                   "role":"*","resource":"*","action":"write"}
                ]}""");
    }

    @Test
    @DisplayName("合法令牌 + 匹配 PERMIT 规则 -> 放行并写 PERMIT 审计")
    void permitFlowAudited() {
        String token = tokens.issue("alice", "reader", 60_000L);
        AccessResponse resp = gateway.decide(token, "docs", "read", Map.of());

        assertTrue(resp.permitted());
        assertEquals("PERMIT", resp.reasonCode());
        assertEquals("reader-read", resp.matchedRuleId());

        AuditRecord last = audit.recent().get(audit.recent().size() - 1);
        assertEquals(AuditOutcome.PERMIT, last.outcome());
        assertEquals("alice", last.subject());
        assertEquals("reader-read", last.matchedRuleId());
        assertEquals("v1", last.policyVersion());
    }

    @Test
    @DisplayName("合法令牌但命中 DENY -> 拒绝并写 DENY/EXPLICIT_DENY 审计")
    void denyFlowAudited() {
        String token = tokens.issue("bob", "reader", 60_000L);
        AccessResponse resp = gateway.decide(token, "docs", "write", Map.of());

        assertFalse(resp.permitted());
        assertEquals("EXPLICIT_DENY", resp.reasonCode());
        AuditRecord last = audit.recent().get(audit.recent().size() - 1);
        assertEquals(AuditOutcome.DENY, last.outcome());
        assertEquals("EXPLICIT_DENY", last.reasonCode());
        assertEquals("deny-all-write", last.matchedRuleId());
    }

    @Test
    @DisplayName("篡改令牌 -> 拒绝原因 BAD_SIGNATURE 并写 TOKEN_INVALID 审计，不放行")
    void tamperedTokenRejectedAndAudited() {
        String token = tokens.issue("bob", "reader", 60_000L);
        String[] parts = token.split("\\.");
        // 用同长度的错误签名整体替换，确定性触发 BAD_SIGNATURE
        parts[2] = "A".repeat(parts[2].length());
        String tampered = String.join(".", parts);

        AccessResponse resp = gateway.decide(tampered, "docs", "read", Map.of());
        assertFalse(resp.permitted());
        assertEquals("BAD_SIGNATURE", resp.reasonCode());

        AuditRecord last = audit.recent().get(audit.recent().size() - 1);
        assertEquals(AuditOutcome.TOKEN_INVALID, last.outcome());
        assertEquals("BAD_SIGNATURE", last.reasonCode());
    }

    @Test
    @DisplayName("过期令牌 -> TOKEN_EXPIRED，审计可区分")
    void expiredTokenRejected() {
        String token = tokens.issue("bob", "reader",
                System.currentTimeMillis() - 10_000L, 1_000L);
        AccessResponse resp = gateway.decide(token, "docs", "read", Map.of());
        assertFalse(resp.permitted());
        assertEquals("TOKEN_EXPIRED", resp.reasonCode());
    }

    @Test
    @DisplayName("轮换过渡 + 热更新联动：旧令牌过渡期可用，新策略整体生效")
    void rotationAndHotReloadEndToEnd() {
        String oldToken = tokens.issue("carol", "reader", 60_000L);
        keyStore.rotate("k-new", System.currentTimeMillis(), 3_600_000L);

        // 过渡期内旧令牌仍能通过令牌层并被判定
        assertTrue(gateway.decide(oldToken, "docs", "read", Map.of()).permitted());

        // 热更新把 reader 读 docs 改为 DENY
        var result = admin.apply("""
                {"version":"v2","rules":[
                  {"id":"reader-read-deny","effect":"DENY",
                   "role":"reader","resource":"docs","action":"read"}
                ]}""");
        assertTrue(result.applied());

        AccessResponse resp = gateway.decide(oldToken, "docs", "read", Map.of());
        assertFalse(resp.permitted());
        assertEquals("EXPLICIT_DENY", resp.reasonCode());
        assertEquals("v2", resp.policyVersion());
        assertEquals("reader-read-deny", resp.matchedRuleId());

        // 新密钥签发的令牌同样按 v2 判定
        String newToken = tokens.issue("carol", "reader", 60_000L);
        AccessResponse resp2 = gateway.decide(newToken, "docs", "read", Map.of());
        assertFalse(resp2.permitted());
    }
}
