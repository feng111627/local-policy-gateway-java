package com.github.feng111627.localpolicygatewayjava.policy;

import com.github.feng111627.localpolicygatewayjava.model.Decision;
import com.github.feng111627.localpolicygatewayjava.model.Policy;
import com.github.feng111627.localpolicygatewayjava.model.Rule;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 策略校验。任何缺失字段、非法取值或规则矛盾都会抛出带具体错误代码的异常，
 * 热更新因此失败并保留上一版策略，绝不让带病策略静默上线。
 */
@Component
public class PolicyValidator {

    public void validate(Policy policy) {
        if (policy == null) {
            throw new PolicyParseException(PolicyError.MISSING_FIELD, "策略对象为 null");
        }
        requireText(policy.policyId(), "policyId");
        if (policy.version() <= 0) {
            throw new PolicyParseException(PolicyError.INVALID_VALUE, "version 必须为正整数，实际为 " + policy.version());
        }
        List<Rule> rules = policy.rules();
        if (rules == null) {
            throw new PolicyParseException(PolicyError.MISSING_FIELD, "缺少 rules 字段");
        }
        if (rules.isEmpty()) {
            throw new PolicyParseException(PolicyError.MISSING_FIELD, "rules 不能为空（默认拒绝由引擎兜底，显式禁止空策略）");
        }

        Set<String> ids = new HashSet<>();
        for (int i = 0; i < rules.size(); i++) {
            Rule rule = rules.get(i);
            String where = "rules[" + i + "]";
            if (rule == null) {
                throw new PolicyParseException(PolicyError.MISSING_FIELD, where + " 为 null");
            }
            requireText(rule.id(), where + ".id");
            if (!ids.add(rule.id())) {
                throw new PolicyParseException(PolicyError.DUPLICATE_RULE_ID, "规则 id 重复: " + rule.id());
            }
            if (rule.effect() != Decision.ALLOW && rule.effect() != Decision.DENY) {
                throw new PolicyParseException(PolicyError.INVALID_VALUE,
                        where + "(" + rule.id() + ").effect 只能是 ALLOW 或 DENY");
            }
            if (rule.priority() < 0) {
                throw new PolicyParseException(PolicyError.INVALID_VALUE,
                        where + "(" + rule.id() + ").priority 不能为负数: " + rule.priority());
            }
            validateConstraints(rule, where, rule.roles(), "roles");
            validateConstraints(rule, where, rule.resources(), "resources");
            validateEnv(rule, where);
        }
        validateContradictions(rules);
    }

    private void validateConstraints(Rule rule, String where, List<String> values, String field) {
        if (values == null) {
            return; // null 表示该维度不做限制，属于合法缺省
        }
        for (String value : values) {
            if (value == null || value.isBlank()) {
                throw new PolicyParseException(PolicyError.INVALID_VALUE,
                        where + "(" + rule.id() + ")." + field + " 含空元素");
            }
        }
    }

    private void validateEnv(Rule rule, String where) {
        Map<String, List<String>> env = rule.env();
        if (env == null) {
            return;
        }
        env.forEach((key, candidates) -> {
            if (key == null || key.isBlank()) {
                throw new PolicyParseException(PolicyError.INVALID_VALUE,
                        where + "(" + rule.id() + ").env 含空键");
            }
            if (candidates == null || candidates.isEmpty()) {
                throw new PolicyParseException(PolicyError.MISSING_FIELD,
                        where + "(" + rule.id() + ").env." + key + " 候选值列表不能为空");
            }
            for (String candidate : candidates) {
                if (candidate == null || candidate.isBlank()) {
                    throw new PolicyParseException(PolicyError.INVALID_VALUE,
                            where + "(" + rule.id() + ").env." + key + " 含空候选值");
                }
            }
        });
    }

    /**
     * 矛盾检测：两条规则在同一优先级上、匹配域互不排斥（角色/资源/环境存在同时满足的可能），
     * 且 effect 相反，则定义为相互矛盾，整份策略拒绝生效。
     */
    private void validateContradictions(List<Rule> rules) {
        Map<Integer, List<Rule>> byPriority = new HashMap<>();
        for (Rule rule : rules) {
            byPriority.computeIfAbsent(rule.priority(), k -> new ArrayList<>()).add(rule);
        }
        for (Map.Entry<Integer, List<Rule>> entry : byPriority.entrySet()) {
            List<Rule> group = entry.getValue();
            for (int i = 0; i < group.size(); i++) {
                for (int j = i + 1; j < group.size(); j++) {
                    Rule a = group.get(i);
                    Rule b = group.get(j);
                    if (a.effect() != b.effect() && canOverlap(a, b)) {
                        throw new PolicyParseException(PolicyError.CONTRADICTORY_RULES,
                                "优先级 " + entry.getKey() + " 上规则 " + a.id() + "(" + a.effect()
                                        + ") 与 " + b.id() + "(" + b.effect()
                                        + ") 匹配域重叠且效果相反，构成矛盾规则");
                    }
                }
            }
        }
    }

    private boolean canOverlap(Rule a, Rule b) {
        return stringSetsOverlap(a.roles(), b.roles())
                && stringSetsOverlap(a.resources(), b.resources())
                && envOverlaps(a.env(), b.env());
    }

    /** null 表示“不限制”；否则需要双方有共同候选值（同值，或任一侧的单段通配 *）。 */
    private boolean stringSetsOverlap(List<String> a, List<String> b) {
        if (a == null || b == null) {
            return true;
        }
        for (String x : a) {
            for (String y : b) {
                if ("*".equals(x) || "*".equals(y) || x.equals(y)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean envOverlaps(Map<String, List<String>> a, Map<String, List<String>> b) {
        if (a == null || b == null) {
            return true;
        }
        for (Map.Entry<String, List<String>> entry : a.entrySet()) {
            List<String> other = b.get(entry.getKey());
            if (other == null) {
                continue; // b 不约束该键
            }
            if (stringSetsOverlap(entry.getValue(), other)) {
                return true;
            }
            return false; // 同一键候选值不相交
        }
        return true;
    }

    private void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new PolicyParseException(PolicyError.MISSING_FIELD, "缺少必填字段 " + field);
        }
    }
}
