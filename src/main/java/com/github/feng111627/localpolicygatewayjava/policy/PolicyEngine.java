package com.github.feng111627.localpolicygatewayjava.policy;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 策略引擎。
 *
 * <ul>
 *   <li>当前版本保存在 {@link AtomicReference} 中，热更新通过一次 CAS 整体替换，
 *       并发判定永远只能看到旧版或新版的完整策略，看不到“更新一半”的中间态。</li>
 *   <li>默认拒绝：无版本、无任何命中规则均拒绝。</li>
 *   <li>多条规则命中时的稳定优先级：
 *       <ol>
 *         <li>priority 数值大者优先；</li>
 *         <li>同优先级时，匹配更具体者优先（具体匹配维度数量多者）；</li>
 *         <li>仍相同时，规则 ID 字典序（完全确定）。</li>
 *       </ol>
 *       同匹配范围、同优先级但效果相反的规则在加载阶段即被判定为矛盾，不会进入引擎。</li>
 * </ul>
 */
public class PolicyEngine {

    private final AtomicReference<Policy> current = new AtomicReference<>();

    /** 整体替换为新版本；空策略视为非法，由调用方在解析阶段拦截。 */
    public void replace(Policy policy) {
        if (policy == null) {
            throw new IllegalArgumentException("policy 不能为 null");
        }
        current.set(policy);
    }

    public Policy current() {
        return current.get();
    }

    public Decision evaluate(AccessRequest request) {
        Policy policy = current.get();
        if (policy == null) {
            return new Decision(false, null, null, DenyReason.NO_POLICY_LOADED,
                    "当前没有任何已生效策略，按默认拒绝处理", null);
        }

        List<Rule> matched = policy.rules().stream()
                .filter(r -> matches(r, request))
                .sorted(ruleComparator())
                .toList();

        if (matched.isEmpty()) {
            return new Decision(false, null, null, DenyReason.NO_RULE_MATCHED,
                    "没有任何规则匹配该请求(role=" + request.role()
                            + ", resource=" + request.resource()
                            + ", action=" + request.action() + ")，按默认拒绝处理",
                    policy.version());
        }

        Rule winner = matched.get(0);
        if (winner.effect() == Effect.PERMIT) {
            return new Decision(true, winner.id(), winner.effect(), null,
                    "命中最高优先级规则 " + winner.id() + "(priority=" + winner.priority()
                            + ", effect=PERMIT)，在 " + matched.size() + " 条命中规则中胜出",
                    policy.version());
        }
        return new Decision(false, winner.id(), winner.effect(), DenyReason.EXPLICIT_DENY,
                "命中最高优先级规则 " + winner.id() + "(priority=" + winner.priority()
                        + ", effect=DENY)，在 " + matched.size() + " 条命中规则中胜出，显式拒绝",
                policy.version());
    }

    private boolean matches(Rule r, AccessRequest req) {
        return dimensionMatches(r.role(), req.role())
                && dimensionMatches(r.resource(), req.resource())
                && dimensionMatches(r.action(), req.action())
                && envMatches(r.env(), req.env() == null ? Map.of() : req.env());
    }

    private boolean dimensionMatches(String pattern, String value) {
        return "*".equals(pattern) || pattern.equals(value);
    }

    /** 规则 env 中的每个等值约束都必须在请求环境里满足。 */
    private boolean envMatches(Map<String, String> constraints, Map<String, String> requestEnv) {
        for (Map.Entry<String, String> c : constraints.entrySet()) {
            if (!c.getValue().equals(requestEnv.get(c.getKey()))) {
                return false;
            }
        }
        return true;
    }

    private Comparator<Rule> ruleComparator() {
        // 1) priority 数值大者优先（取负实现降序）；
        // 2) 同优先级时具体度（非通配维度 + env 约束数）高者优先；
        // 3) 仍相同时按规则 ID 字典序，保证裁决完全确定。
        return Comparator
                .comparingInt((Rule r) -> -r.priority())
                .thenComparingInt((Rule r) -> -specificity(r))
                .thenComparing(Rule::id);
    }

    /** 具体度：非通配的 role/resource/action 各计 1 分，env 约束每条计 1 分。 */
    private int specificity(Rule r) {
        int s = 0;
        if (!"*".equals(r.role())) s++;
        if (!"*".equals(r.resource())) s++;
        if (!"*".equals(r.action())) s++;
        s += r.env().size();
        return s;
    }
}
