package com.github.feng111627.localpolicygatewayjava.policy;

/** 一次访问判定的结果，可解释命中规则与原因。 */
public record Decision(
        boolean permitted,
        String matchedRuleId,
        Effect matchedEffect,
        DenyReason denyReason,
        String message,
        String policyVersion
) {
}
