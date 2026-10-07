package com.github.feng111627.localpolicygatewayjava.tests;

import com.github.feng111627.localpolicygatewayjava.audit.AuditLog;
import com.github.feng111627.localpolicygatewayjava.model.Decision;
import com.github.feng111627.localpolicygatewayjava.model.DecisionRequest;
import com.github.feng111627.localpolicygatewayjava.model.DecisionResponse;
import com.github.feng111627.localpolicygatewayjava.model.DenyReason;
import com.github.feng111627.localpolicygatewayjava.model.PolicyUpdateResult;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyEngine;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyParser;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyRepository;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyValidator;
import com.github.feng111627.localpolicygatewayjava.service.GatewayService;
import com.github.feng111627.localpolicygatewayjava.token.KeyStore;
import com.github.feng111627.localpolicygatewayjava.token.LocalTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 主线三：策略运行期热更新的原子生效、失败保留上一版、非法策略可区分拒绝，
 * 以及并发判定期间看不到半成品、每次判定都留审计。
 */
@DisplayName("主线三：策略热更新（原子生效/失败保留/并发一致/审计）")
class PolicyHotReloadTest {

    private PolicyRepository repository;
    private PolicyParser parser;
    private PolicyValidator validator;
    private GatewayService gateway;
    private AuditLog auditLog;
    private LocalTokenService tokens;

    private static final String V1_JSON = """
            {
              "policyId": "hot",
              "name": "v1",
              "version": 1,
              "rules": [
                {"id": "v1-allow", "effect": "ALLOW", "priority": 100,
                 "roles": ["viewer"], "resources": ["docs/*"], "env": {"env": ["dev"]}}
              ]
            }
            """;

    private static final String V2_JSON = """
            {
              "policyId": "hot",
              "name": "v2",
              "version": 2,
              "rules": [
                {"id": "v2-deny", "effect": "DENY", "priority": 100,
                 "roles": ["viewer"], "resources": ["docs/*"], "env": {"env": ["dev"]}}
              ]
            }
            """;

    @BeforeEach
    void setUp() {
        repository = new PolicyRepository();
        parser = new PolicyParser();
        validator = new PolicyValidator();
        KeyStore keyStore = new KeyStore(Clock.systemUTC());
        tokens = new LocalTokenService(keyStore, Clock.systemUTC());
        auditLog = new AuditLog();
        PolicyEngine engine = new PolicyEngine(repository);
        gateway = new GatewayService(tokens, engine, repository, parser, validator, keyStore, auditLog);
        PolicyUpdateResult init = gateway.reloadPolicy(V1_JSON);
        assertTrue(init.success());
    }

    private String bearer(String... roles) {
        return "Bearer " + tokens.issue("alice", List.of(roles), Duration.ofHours(1));
    }

    private DecisionRequest docsDev() {
        return new DecisionRequest("docs/a", Map.of("env", "dev"));
    }

    @Nested
    @DisplayName("热更新生效与保留用例")
    class ReloadCases {

        @Test
        @DisplayName("用例3.1 合法 v2 整体生效：同一请求从放行变拒绝，响应带新版本号")
        void validReloadTakesEffectAtomically() {
            DecisionResponse before = gateway.decide(bearer("viewer"), docsDev());
            assertEquals(Decision.ALLOW, before.decision());
            assertEquals(1, before.policyVersion());

            PolicyUpdateResult result = gateway.reloadPolicy(V2_JSON);
            assertTrue(result.success());
            assertEquals(2, result.activeVersion());

            DecisionResponse after = gateway.decide(bearer("viewer"), docsDev());
            assertEquals(Decision.DENY, after.decision());
            assertEquals("v2-deny", after.matchedRuleId());
            assertEquals(2, after.policyVersion());
        }

        @Test
        @DisplayName("用例3.2 JSON 语法错误 → 更新失败，错误码 SYNTAX_ERROR，v1 保留")
        void syntaxErrorKeepsOldVersion() {
            PolicyUpdateResult result = gateway.reloadPolicy("{ not-json");
            assertFalse(result.success());
            assertEquals("SYNTAX_ERROR", result.errorCode());
            assertEquals(1, result.activeVersion());
            // v1 仍然完整可用
            assertEquals(Decision.ALLOW, gateway.decide(bearer("viewer"), docsDev()).decision());
        }

        @Test
        @DisplayName("用例3.3 缺少必填字段 → MISSING_FIELD，旧版保留")
        void missingFieldKeepsOldVersion() {
            String bad = """
                    {"policyId": "hot", "version": 3, "rules": [
                      {"effect": "ALLOW", "priority": 1, "resources": ["x"]}
                    ]}
                    """;
            PolicyUpdateResult result = gateway.reloadPolicy(bad);
            assertFalse(result.success());
            assertEquals("MISSING_FIELD", result.errorCode());
            assertEquals(1, result.activeVersion());
        }

        @Test
        @DisplayName("用例3.4 同优先级矛盾规则 → CONTRADICTORY_RULES，旧版保留")
        void contradictionKeepsOldVersion() {
            String bad = """
                    {"policyId": "hot", "version": 3, "rules": [
                      {"id": "a", "effect": "ALLOW", "priority": 50, "roles": ["r"], "resources": ["x"], "env": null},
                      {"id": "b", "effect": "DENY",  "priority": 50, "roles": ["r"], "resources": ["x"], "env": null}
                    ]}
                    """;
            PolicyUpdateResult result = gateway.reloadPolicy(bad);
            assertFalse(result.success());
            assertEquals("CONTRADICTORY_RULES", result.errorCode());
            assertEquals(1, result.activeVersion());
        }

        @Test
        @DisplayName("用例3.5 版本号不大于当前版本 → STALE_VERSION，旧版保留")
        void staleVersionKeepsOldVersion() {
            PolicyUpdateResult result = gateway.reloadPolicy(V1_JSON);
            assertFalse(result.success());
            assertEquals("STALE_VERSION", result.errorCode());
            assertEquals(1, result.activeVersion());
        }

        @Test
        @DisplayName("用例3.6 非法 effect 取值 → INVALID_VALUE，旧版保留")
        void invalidValueKeepsOldVersion() {
            String bad = """
                    {"policyId": "hot", "version": 3, "rules": [
                      {"id": "a", "effect": "MAYBE", "priority": 50, "roles": ["r"], "resources": ["x"], "env": null}
                    ]}
                    """;
            PolicyUpdateResult result = gateway.reloadPolicy(bad);
            assertFalse(result.success());
            assertEquals("INVALID_VALUE", result.errorCode());
        }
    }

    @Nested
    @DisplayName("并发与审计用例")
    class ConcurrencyAuditCases {

        @Test
        @DisplayName("用例3.7 并发判定 + 热更新：所有判定要么基于 v1 要么基于 v2，绝不出现半成品")
        void concurrentDecisionsSeeOnlyWholeVersions() throws Exception {
            String token = bearer("viewer");
            int threads = 8;
            int perThread = 200;
            ExecutorService pool = Executors.newFixedThreadPool(threads + 1);
            CountDownLatch start = new CountDownLatch(1);
            AtomicInteger v1Seen = new AtomicInteger();
            AtomicInteger v2Seen = new AtomicInteger();
            AtomicInteger weird = new AtomicInteger();

            for (int t = 0; t < threads; t++) {
                pool.submit(() -> {
                    try {
                        start.await();
                        for (int i = 0; i < perThread; i++) {
                            DecisionResponse r = gateway.decide(token, docsDev());
                            if (r.policyVersion() == 1 && r.decision() == Decision.ALLOW) {
                                v1Seen.incrementAndGet();
                            } else if (r.policyVersion() == 2 && r.decision() == Decision.DENY) {
                                v2Seen.incrementAndGet();
                            } else {
                                weird.incrementAndGet();
                            }
                        }
                    } catch (InterruptedException ignored) {
                        Thread.currentThread().interrupt();
                    }
                });
            }
            pool.submit(() -> {
                try {
                    start.await();
                    gateway.reloadPolicy(V2_JSON);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            });

            start.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(20, TimeUnit.SECONDS));
            assertEquals(0, weird.get(), "出现了既非 v1/ALLOW 也非 v2/DENY 的半成品视图");
            assertEquals(threads * perThread, v1Seen.get() + v2Seen.get());
            assertTrue(v2Seen.get() > 0, "热更新后应有判定落在 v2");
        }

        @Test
        @DisplayName("用例3.8 每次判定都留审计记录，放行与拒绝（含无令牌）均可追溯且原因可区分")
        void everyDecisionIsAudited() {
            auditLog.clear();
            gateway.decide(bearer("viewer"), docsDev());           // ALLOW
            gateway.reloadPolicy(V2_JSON);
            gateway.decide(bearer("viewer"), docsDev());           // EXPLICITLY_DENIED
            gateway.decide(null, docsDev());                       // NO_TOKEN

            var events = auditLog.events();
            assertEquals(3, events.size());
            assertEquals(Decision.ALLOW, events.get(0).decision());
            assertEquals("v1-allow", events.get(0).matchedRuleId());
            assertEquals(Decision.DENY, events.get(1).decision());
            assertEquals(DenyReason.EXPLICITLY_DENIED, events.get(1).denyReason());
            assertEquals(Decision.DENY, events.get(2).decision());
            assertEquals(DenyReason.NO_TOKEN, events.get(2).denyReason());
            events.forEach(e -> {
                assertTrue(e.timestamp() != null && e.resource() != null);
            });
        }
    }
}
