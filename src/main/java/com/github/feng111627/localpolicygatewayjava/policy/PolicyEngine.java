package com.github.feng111627.localpolicygatewayjava.policy;

import com.github.feng111627.localpolicygatewayjava.model.Decision;
import com.github.feng111627.localpolicygatewayjava.model.DecisionRequest;
import com.github.feng111627.localpolicygatewayjava.model.DenyReason;
import com.github.feng111627.localpolicygatewayjava.model.Policy;
import com.github.feng111627.localpolicygatewayjava.model.Rule;
import com.github.feng111627.localpolicygatewayjava.model.TokenClaims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * 策略求值引擎。
 *
 * <p>优先级与冲突规则（全部可解释、结果稳定）：
 * <ol>
 *   <li>先筛出全部匹配规则；一条都没有 → 默认拒绝（NO_MATCHING_RULE）；</li>
 *   <li>匹配规则按 {@code priority} 降序，只在最高优先级层内决策；</li>
 *   <li>最高层全部同效果 → 取该效果，命中规则取层内 id 字典序第一条（稳定可复现）；</li>
 *   <li>最高层同时存在 ALLOW 与 DENY → 视为矛盾，拒绝（CONTRADICTORY_RULES）。
 *       装载期校验已禁止静态可判定的同优先级矛盾；此分支只用于环境属性造成的动态重叠，
 *       保证矛盾永不被静默跳过。</li>
 * </ol>
 */
@Component
public class PolicyEngine {

    private final PolicyRepository repository;

    @Autowired
    public PolicyEngine(PolicyRepository repository) {
        this.repository = repository;
    }

    public Evaluation evaluate(TokenClaims claims, DecisionRequest request) {
        return evaluate(repository.current(), claims, request);
    }

    /**
     * 对调用方给定的不可变策略快照求值。热更新并发场景下，判定服务在令牌校验通过后
     * 抓取一次快照并传入这里，保证求值、响应版本号、审计三者来自同一版策略。
     */
    public Evaluation evaluate(Policy policy, TokenClaims claims, DecisionRequest request) {
        if (policy == null) {
            return Evaluation.deny(null, DenyReason.POLICY_UNAVAILABLE,
                    "当前没有任何生效策略，防御性拒绝");
        }
        List<String> roles = claims.roles() == null ? List.of() : claims.roles();
        String resource = request.resource() == null ? "" : request.resource();
        Map<String, String> env = request.env() == null ? Map.of() : request.env();

        List<Rule> matched = policy.rules().stream()
                .filter(rule -> matches(rule, roles, resource, env))
                .toList();

        if (matched.isEmpty()) {
            return Evaluation.deny(null, DenyReason.NO_MATCHING_RULE,
                    "没有规则匹配 resource=" + resource + "、roles=" + roles
                            + "、env=" + env + "，按默认拒绝处理（策略 "
                            + policy.policyId() + " v" + policy.version() + "）");
        }

        int highest = matched.stream().mapToInt(Rule::priority).max().orElseThrow();
        List<Rule> topLevel = matched.stream()
                .filter(rule -> rule.priority() == highest)
                .sorted(Comparator.comparing(Rule::id))
                .toList();

        boolean hasAllow = topLevel.stream().anyMatch(r -> r.effect() == Decision.ALLOW);
        boolean hasDeny = topLevel.stream().anyMatch(r -> r.effect() == Decision.DENY);
        if (hasAllow && hasDeny) {
            return Evaluation.deny(null, DenyReason.CONTRADICTORY_RULES,
                    "最高优先级 " + highest + " 层内同时命中放行与拒绝规则 "
                            + topLevel.stream().map(r -> r.id() + "=" + r.effect()).toList()
                            + "，无法稳定决策，按拒绝处理");
        }

        Rule winner = topLevel.get(0);
        if (winner.effect() == Decision.ALLOW) {
            return Evaluation.allow(winner.id(),
                    "命中规则 " + winner.id() + "（优先级 " + winner.priority() + "，最高优先级层一致 ALLOW），放行");
        }
        return Evaluation.deny(winner.id(), DenyReason.EXPLICITLY_DENIED,
                "命中规则 " + winner.id() + "（优先级 " + winner.priority() + "，最高优先级层一致 DENY），拒绝");
    }

    boolean matches(Rule rule, List<String> roles, String resource, Map<String, String> env) {
        return matchesRoles(rule, roles)
                && matchesResource(rule, resource)
                && matchesEnv(rule, env);
    }

    private boolean matchesRoles(Rule rule, List<String> roles) {
        List<String> required = rule.roles();
        if (required == null || required.isEmpty()) {
            return true;
        }
        return required.stream().anyMatch(roles::contains);
    }

    private boolean matchesResource(Rule rule, String resource) {
        List<String> patterns = rule.resources();
        if (patterns == null || patterns.isEmpty()) {
            return true;
        }
        return patterns.stream().anyMatch(pattern -> matchPattern(pattern, resource));
    }

    /** 精确匹配；支持末尾单段通配，例如 {@code docs/*} 匹配 {@code docs/readme}，但不跨 {@code /}。 */
    private boolean matchPattern(String pattern, String value) {
        if ("*".equals(pattern)) {
            return true;
        }
        if (pattern.endsWith("/*")) {
            String prefix = pattern.substring(0, pattern.length() - 1); // 保留到 '/'
            if (!value.startsWith(prefix)) {
                return false;
            }
            String tail = value.substring(prefix.length());
            return !tail.isEmpty() && !tail.contains("/");
        }
        return Objects.equals(pattern, value);
    }

    private boolean matchesEnv(Rule rule, Map<String, String> env) {
        Map<String, List<String>> constraints = rule.env();
        if (constraints == null || constraints.isEmpty()) {
            return true;
        }
        for (Map.Entry<String, List<String>> entry : constraints.entrySet()) {
            String actual = env.get(entry.getKey());
            if (actual == null) {
                return false; // 约束键必须存在，缺失即不匹配，绝不静默放宽
            }
            List<String> candidates = entry.getValue();
            if (!candidates.contains(actual)) {
                return false;
            }
        }
        return true;
    }
}
