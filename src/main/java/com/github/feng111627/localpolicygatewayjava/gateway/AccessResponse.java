package com.github.feng111627.localpolicygatewayjava.gateway;

/** 网关判定响应：可解释的结论。 */
public record AccessResponse(
        boolean permitted,
        String reasonCode,
        String matchedRuleId,
        String policyVersion,
        String requestId
) {
}
