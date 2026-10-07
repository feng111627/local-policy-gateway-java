package com.github.feng111627.localpolicygatewayjava.policy;

import java.util.Map;

/** 单条策略规则（解析后的不可变形态）。 */
public record Rule(
        String id,
        Effect effect,
        int priority,
        String role,
        String resource,
        String action,
        Map<String, String> env
) {
}
