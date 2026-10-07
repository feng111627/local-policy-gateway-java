package com.github.feng111627.localpolicygatewayjava.tests;

import com.github.feng111627.localpolicygatewayjava.model.Decision;
import com.github.feng111627.localpolicygatewayjava.model.DecisionRequest;
import com.github.feng111627.localpolicygatewayjava.model.DenyReason;
import com.github.feng111627.localpolicygatewayjava.model.Policy;
import com.github.feng111627.localpolicygatewayjava.model.Rule;
import com.github.feng111627.localpolicygatewayjava.model.TokenClaims;
import com.github.feng111627.localpolicygatewayjava.policy.Evaluation;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyEngine;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyRepository;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 主线一：基于角色 + 资源 + 环境属性的放行 / 拒绝判定，
 * 覆盖默认拒绝、优先级、稳定命中规则与可解释原因。
 */
@DisplayName("主线一：策略访问判定（放行/拒绝/优先级/默认拒绝）")
class AccessDecisionPolicyTest {

    private PolicyRepository repository;
    private PolicyEngine engine;

    private static final Rule ALLOW_VIEWER = new Rule("allow-viewer", Decision.ALLOW, 100,
            List.of("viewer"), List.of("docs/*"), Map.of("env", List.of("dev")));
    private static final Rule DENY_VIEWER_PROD = new Rule("deny-viewer-prod", Decision.DENY, 200,
            List.of("viewer"), List.of("docs/*"), Map.of("env", List.of("prod")));
    private static final Rule ALLOW_ADMIN_PROD = new Rule("allow-admin-prod", Decision.ALLOW, 300,
            List.of("admin"), List.of("docs/*"), Map.of("env", List.of("prod")));

    @BeforeEach
    void setUp() {
        repository = new PolicyRepository();
        engine = new PolicyEngine(repository);
        Policy policy = new Policy("p", "test", 1,
                List.of(DENY_VIEWER_PROD, ALLOW_VIEWER, ALLOW_ADMIN_PROD));
        new PolicyValidator().validate(policy);
        repository.replace(policy);
    }

    private Evaluation evaluate(List<String> roles, String resource, Map<String, String> env) {
        TokenClaims claims = new TokenClaims("user-1", roles, 0, Long.MAX_VALUE);
        return engine.evaluate(claims, new DecisionRequest(resource, env));
    }

    @Nested
    @DisplayName("放行用例")
    class AllowCases {

        @Test
        @DisplayName("用例1.1 viewer 在 dev 访问 docs/a → 命中 allow-viewer 放行")
        void allowViewerInDev() {
            Evaluation result = evaluate(List.of("viewer"), "docs/a", Map.of("env", "dev"));
            assertEquals(Decision.ALLOW, result.decision());
            assertEquals("allow-viewer", result.matchedRuleId());
            assertNull(result.denyReason());
            assertTrue(result.message().contains("allow-viewer"));
        }

        @Test
        @DisplayName("用例1.2 admin 在 prod 访问 docs/a → 高优先级 allow-admin-prod 放行")
        void allowAdminInProdByHigherPriority() {
            Evaluation result = evaluate(List.of("admin"), "docs/a", Map.of("env", "prod"));
            assertEquals(Decision.ALLOW, result.decision());
            assertEquals("allow-admin-prod", result.matchedRuleId());
        }

        @Test
        @DisplayName("用例1.3 多角色用户在 prod 同时命中 deny(200) 与 allow(300) → 高优先级放行")
        void higherPriorityWinsWhenBothMatch() {
            Evaluation result = evaluate(List.of("viewer", "admin"), "docs/a", Map.of("env", "prod"));
            assertEquals(Decision.ALLOW, result.decision());
            assertEquals("allow-admin-prod", result.matchedRuleId());
        }
    }

    @Nested
    @DisplayName("拒绝用例")
    class DenyCases {

        @Test
        @DisplayName("用例1.4 viewer 在 prod 访问 docs/a → 命中显式 DENY 规则")
        void explicitDenyViewerInProd() {
            Evaluation result = evaluate(List.of("viewer"), "docs/a", Map.of("env", "prod"));
            assertEquals(Decision.DENY, result.decision());
            assertEquals("deny-viewer-prod", result.matchedRuleId());
            assertEquals(DenyReason.EXPLICITLY_DENIED, result.denyReason());
        }

        @Test
        @DisplayName("用例1.5 无任何规则匹配 → 默认拒绝 NO_MATCHING_RULE")
        void defaultDenyWhenNoRuleMatches() {
            Evaluation result = evaluate(List.of("viewer"), "secret/db", Map.of("env", "dev"));
            assertEquals(Decision.DENY, result.decision());
            assertNull(result.matchedRuleId());
            assertEquals(DenyReason.NO_MATCHING_RULE, result.denyReason());
            assertNotNull(result.message());
        }

        @Test
        @DisplayName("用例1.6 环境属性缺失（规则要求 env 但请求未带）→ 不匹配 → 默认拒绝")
        void missingEnvAttributeDoesNotMatch() {
            Evaluation result = evaluate(List.of("viewer"), "docs/a", Map.of());
            assertEquals(Decision.DENY, result.decision());
            assertEquals(DenyReason.NO_MATCHING_RULE, result.denyReason());
        }

        @Test
        @DisplayName("用例1.7 通配不跨路径段：docs/x/y 不被 docs/* 匹配 → 默认拒绝")
        void wildcardDoesNotCrossSegment() {
            Evaluation result = evaluate(List.of("viewer"), "docs/x/y", Map.of("env", "dev"));
            assertEquals(Decision.DENY, result.decision());
            assertEquals(DenyReason.NO_MATCHING_RULE, result.denyReason());
        }

        @Test
        @DisplayName("用例1.8 同优先级层动态矛盾（环境约束重叠）→ CONTRADICTORY_RULES 拒绝，不静默跳过")
        void contradictoryDynamicOverlapIsRejected() {
            // 装载校验做的是字符串集合级静态比较：docs/* 与 docs/readme 字面上不相交，允许装载；
            // 但请求 docs/readme 在运行时同时匹配两条同优先级规则，最高层出现矛盾必须拒绝。
            Rule allow = new Rule("dyn-allow", Decision.ALLOW, 50,
                    null, List.of("docs/*"), null);
            Rule deny = new Rule("dyn-deny", Decision.DENY, 50,
                    null, List.of("docs/readme"), null);
            Policy policy = new Policy("p2", "test", 2, List.of(allow, deny));
            new PolicyValidator().validate(policy);
            repository.replace(policy);

            Evaluation result = evaluate(List.of(), "docs/readme", Map.of());
            assertEquals(Decision.DENY, result.decision());
            assertEquals(DenyReason.CONTRADICTORY_RULES, result.denyReason());
            assertTrue(result.message().contains("dyn-allow"));
            assertTrue(result.message().contains("dyn-deny"));
        }
    }
}
