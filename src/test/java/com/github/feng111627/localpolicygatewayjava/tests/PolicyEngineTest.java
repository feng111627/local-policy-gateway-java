package com.github.feng111627.localpolicygatewayjava.tests;

import com.github.feng111627.localpolicygatewayjava.policy.AccessRequest;
import com.github.feng111627.localpolicygatewayjava.policy.Decision;
import com.github.feng111627.localpolicygatewayjava.policy.DenyReason;
import com.github.feng111627.localpolicygatewayjava.policy.Effect;
import com.github.feng111627.localpolicygatewayjava.policy.Policy;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyEngine;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 策略裁决主线：放行 / 默认拒绝 / 优先级与冲突处理 / 环境属性。 */
class PolicyEngineTest {

    private PolicyEngine engine;
    private final PolicyParser parser = new PolicyParser();

    @BeforeEach
    void setUp() {
        engine = new PolicyEngine();
    }

    private static AccessRequest req(String role, String resource, String action,
                                     Map<String, String> env) {
        return new AccessRequest(role, resource, action, env);
    }

    @Nested
    @DisplayName("放行主线")
    class Permit {

        @Test
        @DisplayName("高优先级管理员规则放行任意资源")
        void adminPermitted() {
            engine.replace(parser.parse("""
                    {"version":"v1","rules":[
                      {"id":"admin-all","effect":"PERMIT","priority":100,
                       "role":"admin","resource":"*","action":"*"}
                    ]}"""));
            Decision d = engine.evaluate(req("admin", "secrets", "write", Map.of()));
            assertTrue(d.permitted());
            assertEquals("admin-all", d.matchedRuleId());
            assertNull(d.denyReason());
        }

        @Test
        @DisplayName("普通读者在非生产环境读文档放行")
        void readerPermittedInDev() {
            engine.replace(defaultPolicy());
            Decision d = engine.evaluate(
                    req("reader", "docs", "read", Map.of("env", "dev")));
            assertTrue(d.permitted());
            assertEquals("reader-read-docs", d.matchedRuleId());
        }

        @Test
        @DisplayName("命中结果消息包含胜出规则与命中数量，可解释")
        void messageExplainsWinner() {
            engine.replace(defaultPolicy());
            Decision d = engine.evaluate(
                    req("reader", "docs", "read", Map.of("env", "dev")));
            assertNotNull(d.message());
            assertTrue(d.message().contains("reader-read-docs"));
        }
    }

    @Nested
    @DisplayName("拒绝主线")
    class Deny {

        @Test
        @DisplayName("未加载任何策略时默认拒绝，原因 NO_POLICY_LOADED")
        void denyWhenNoPolicy() {
            Decision d = engine.evaluate(req("reader", "docs", "read", Map.of()));
            assertFalse(d.permitted());
            assertEquals(DenyReason.NO_POLICY_LOADED, d.denyReason());
        }

        @Test
        @DisplayName("无规则匹配时默认拒绝，原因 NO_RULE_MATCHED")
        void denyWhenNoMatch() {
            engine.replace(defaultPolicy());
            Decision d = engine.evaluate(
                    req("auditor", "payments", "read", Map.of()));
            assertFalse(d.permitted());
            assertEquals(DenyReason.NO_RULE_MATCHED, d.denyReason());
            assertNull(d.matchedRuleId());
        }

        @Test
        @DisplayName("显式拒绝写操作，原因 EXPLICIT_DENY")
        void explicitDenyWrite() {
            engine.replace(defaultPolicy());
            Decision d = engine.evaluate(
                    req("reader", "docs", "write", Map.of("env", "dev")));
            assertFalse(d.permitted());
            assertEquals(DenyReason.EXPLICIT_DENY, d.denyReason());
            assertEquals("deny-write", d.matchedRuleId());
            assertEquals(Effect.DENY, d.matchedEffect());
        }

        @Test
        @DisplayName("环境属性命中更具体的 DENY：生产环境读文档被拒")
        void envSpecificDenyWins() {
            engine.replace(defaultPolicy());
            Decision d = engine.evaluate(
                    req("reader", "docs", "read", Map.of("env", "prod")));
            assertFalse(d.permitted());
            assertEquals("reader-read-docs-prod-deny", d.matchedRuleId());
        }
    }

    @Nested
    @DisplayName("优先级与冲突稳定性")
    class Priority {

        @Test
        @DisplayName("priority 数值大的规则胜出，与声明顺序无关")
        void higherPriorityWins() {
            Policy p = parser.parse("""
                    {"version":"v1","rules":[
                      {"id":"low-deny","effect":"DENY","priority":1,
                       "role":"r","resource":"x","action":"*"},
                      {"id":"high-permit","effect":"PERMIT","priority":10,
                       "role":"r","resource":"x","action":"*"}
                    ]}""");
            engine.replace(p);
            Decision d = engine.evaluate(req("r", "x", "read", Map.of()));
            assertTrue(d.permitted());
            assertEquals("high-permit", d.matchedRuleId());
        }

        @Test
        @DisplayName("同优先级时更具体(非通配/有env约束)的规则胜出")
        void specificityBreaksTie() {
            Policy p = parser.parse("""
                    {"version":"v1","rules":[
                      {"id":"broad","effect":"DENY","priority":5,
                       "role":"r","resource":"*","action":"*"},
                      {"id":"narrow","effect":"PERMIT","priority":5,
                       "role":"r","resource":"x","action":"*"}
                    ]}""");
            engine.replace(p);
            Decision d = engine.evaluate(req("r", "x", "read", Map.of()));
            assertTrue(d.permitted());
            assertEquals("narrow", d.matchedRuleId());
        }

        @Test
        @DisplayName("同优先级同具体度且同效果时按规则 ID 字典序选中，结果稳定可复现")
        void ruleIdBreaksTieStably() {
            String json = """
                    {"version":"v1","rules":[
                      {"id":"z-rule","effect":"PERMIT","priority":5,
                       "role":"r","resource":"x","action":"*"},
                      {"id":"a-rule","effect":"PERMIT","priority":5,
                       "role":"r","resource":"x","action":"*"}
                    ]}""";
            engine.replace(parser.parse(json));
            Decision first = engine.evaluate(req("r", "x", "read", Map.of()));
            engine.replace(parser.parse(json));
            Decision second = engine.evaluate(req("r", "x", "read", Map.of()));
            assertEquals(first.matchedRuleId(), second.matchedRuleId());
            assertEquals("a-rule", first.matchedRuleId());
        }

        @Test
        @DisplayName("同范围同优先级但效果相反在加载期即为矛盾，引擎永远不会收到这种歧义")
        void oppositeEffectsAreContradictionAtLoad() {
            com.github.feng111627.localpolicygatewayjava.policy.PolicyLoadException e =
                    assertThrows(com.github.feng111627.localpolicygatewayjava.policy.PolicyLoadException.class,
                            () -> parser.parse("""
                                    {"version":"v1","rules":[
                                      {"id":"z-rule","effect":"PERMIT","priority":5,
                                       "role":"r","resource":"x","action":"*"},
                                      {"id":"a-rule","effect":"DENY","priority":5,
                                       "role":"r","resource":"x","action":"*"}
                                    ]}"""));
            assertEquals(com.github.feng111627.localpolicygatewayjava.policy.PolicyLoadFailure.CONTRADICTION,
                    e.reason());
        }
    }

    private Policy defaultPolicy() {
        return parser.parse("""
                {"version":"default-v1","rules":[
                  {"id":"admin-all","effect":"PERMIT","priority":100,
                   "role":"admin","resource":"*","action":"*"},
                  {"id":"reader-read-docs","effect":"PERMIT","priority":10,
                   "role":"reader","resource":"docs","action":"read"},
                  {"id":"reader-read-docs-prod-deny","effect":"DENY","priority":20,
                   "role":"reader","resource":"docs","action":"read","env":{"env":"prod"}},
                  {"id":"deny-write","effect":"DENY","priority":5,
                   "role":"*","resource":"*","action":"write"}
                ]}""");
    }
}
