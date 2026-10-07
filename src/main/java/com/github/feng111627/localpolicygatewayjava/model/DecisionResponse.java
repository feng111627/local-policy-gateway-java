package com.github.feng111627.localpolicygatewayjava.model;

/**
 * 访问判定结果，必须能解释“命中哪条规则 / 为什么放行或拒绝”。
 *
 * @param decision     ALLOW / DENY
 * @param reason       放行或拒绝原因
 * @param matchedRuleId 命中规则的 id；无规则命中或令牌阶段拒绝时为 null
 * @param policyId     判定时使用的策略标识
 * @param policyVersion 判定时使用的策略版本
 * @param subject      令牌主体（角色来源）
 */
public record DecisionResponse(
        Decision decision,
        String reason,
        String matchedRuleId,
        String policyId,
        long policyVersion,
        String subject
) {
}
