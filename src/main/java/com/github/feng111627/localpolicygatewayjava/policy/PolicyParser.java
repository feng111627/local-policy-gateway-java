package com.github.feng111627.localpolicygatewayjava.policy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * JSON 文本 -> {@link Policy}。
 *
 * <p>校验责任：语法错误、必填字段缺失、取值非法、规则 ID 重复、同优先级同匹配键矛盾
 * 都不会被静默跳过，而是以可区分的 {@link PolicyLoadFailure} 拒绝整版策略。
 */
public class PolicyParser {

    private static final Set<String> VALID_EFFECTS = Set.of("PERMIT", "DENY");
    private static final Set<String> REQUIRED_RULE_FIELDS = Set.of("id", "effect", "role", "resource");

    private final ObjectMapper mapper = new ObjectMapper();

    public Policy parse(String json) {
        JsonNode root;
        try {
            root = mapper.readTree(json == null ? "" : json);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new PolicyLoadException(PolicyLoadFailure.SYNTAX_ERROR,
                    "策略不是合法 JSON: " + e.getOriginalMessage());
        } catch (Exception e) {
            throw new PolicyLoadException(PolicyLoadFailure.SYNTAX_ERROR,
                    "策略不是合法 JSON: " + e.getMessage());
        }
        if (root == null || !root.isObject()) {
            throw new PolicyLoadException(PolicyLoadFailure.SYNTAX_ERROR, "策略根节点必须是 JSON 对象");
        }

        JsonNode rulesNode = root.get("rules");
        if (rulesNode == null || rulesNode.isNull()) {
            throw new PolicyLoadException(PolicyLoadFailure.MISSING_FIELD, "缺少必填字段: rules");
        }
        if (!rulesNode.isArray()) {
            throw new PolicyLoadException(PolicyLoadFailure.INVALID_VALUE, "rules 必须是数组");
        }

        String version = root.has("version") && root.get("version").isTextual()
                ? root.get("version").asText() : "unversioned";

        List<Rule> rules = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        for (int i = 0; i < rulesNode.size(); i++) {
            JsonNode rn = rulesNode.get(i);
            String where = "rules[" + i + "]";
            if (!rn.isObject()) {
                throw new PolicyLoadException(PolicyLoadFailure.INVALID_VALUE, where + " 必须是对象");
            }
            for (String field : REQUIRED_RULE_FIELDS) {
                JsonNode v = rn.get(field);
                if (v == null || v.isNull() || (v.isTextual() && v.asText().isBlank())) {
                    throw new PolicyLoadException(PolicyLoadFailure.MISSING_FIELD,
                            where + " 缺少必填字段或字段为空: " + field);
                }
            }

            String id = rn.get("id").asText();
            if (!ids.add(id)) {
                throw new PolicyLoadException(PolicyLoadFailure.DUPLICATE_RULE_ID,
                        "规则 ID 重复: " + id);
            }

            String effectText = rn.get("effect").asText().trim().toUpperCase();
            if (!VALID_EFFECTS.contains(effectText)) {
                throw new PolicyLoadException(PolicyLoadFailure.INVALID_VALUE,
                        where + " effect 非法: " + effectText + "（只允许 PERMIT/DENY）");
            }
            Effect effect = Effect.valueOf(effectText);

            int priority = 0;
            if (rn.has("priority") && !rn.get("priority").isNull()) {
                JsonNode p = rn.get("priority");
                if (!p.isInt() && !p.isLong()) {
                    throw new PolicyLoadException(PolicyLoadFailure.INVALID_VALUE,
                            where + " priority 必须是整数");
                }
                priority = p.asInt();
            }

            String role = rn.get("role").asText();
            String resource = rn.get("resource").asText();
            String action = rn.has("action") && rn.get("action").isTextual()
                    && !rn.get("action").asText().isBlank()
                    ? rn.get("action").asText() : "*";
            for (String f : new String[]{"role", "resource", "action"}) {
                String val = switch (f) {
                    case "role" -> role;
                    case "resource" -> resource;
                    default -> action;
                };
                if (val.contains(":")) {
                    throw new PolicyLoadException(PolicyLoadFailure.INVALID_VALUE,
                            where + " " + f + " 不允许包含 ':' 字符: " + val);
                }
            }

            Map<String, String> env = new LinkedHashMap<>();
            if (rn.has("env") && !rn.get("env").isNull()) {
                JsonNode en = rn.get("env");
                if (!en.isObject()) {
                    throw new PolicyLoadException(PolicyLoadFailure.INVALID_VALUE,
                            where + " env 必须是对象");
                }
                en.fields().forEachRemaining(e -> env.put(e.getKey(), e.getValue().asText()));
            }

            rules.add(new Rule(id, effect, priority, role, resource, action,
                    Map.copyOf(env)));
        }

        detectContradictions(rules);
        return new Policy(version, List.copyOf(rules));
    }

    /**
     * 矛盾定义：两条规则的匹配键（role/resource/action/env 约束集合）完全一致、
     * 优先级相同，但 effect 相反。此时命中结果不确定，必须拒绝整版加载。
     */
    private void detectContradictions(List<Rule> rules) {
        record Key(String role, String resource, String action, Map<String, String> env) {
        }
        Map<Key, Rule> seen = new HashMap<>();
        for (Rule r : rules) {
            Key k = new Key(r.role(), r.resource(), r.action(), r.env());
            Rule prev = seen.get(k);
            if (prev != null && prev.priority() == r.priority()
                    && prev.effect() != r.effect()) {
                throw new PolicyLoadException(PolicyLoadFailure.CONTRADICTION,
                        "规则矛盾: " + prev.id() + " 与 " + r.id()
                                + " 匹配范围与优先级相同但效果相反，无法稳定裁决");
            }
            if (prev == null || r.priority() > prev.priority()) {
                seen.put(k, r);
            }
        }
    }
}
