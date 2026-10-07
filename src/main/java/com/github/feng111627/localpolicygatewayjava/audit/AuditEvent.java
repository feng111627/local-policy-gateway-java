package com.github.feng111627.localpolicygatewayjava.audit;

import com.github.feng111627.localpolicygatewayjava.model.Decision;
import com.github.feng111627.localpolicygatewayjava.model.DenyReason;

import java.time.Instant;

/**
 * 一次判定的可追溯审计记录。每次判定（无论放行还是拒绝）都会落一条。
 */
public record AuditEvent(
        Instant timestamp,
        String subject,
        String resource,
        Decision decision,
        DenyReason denyReason,
        String matchedRuleId,
        String policyId,
        long policyVersion,
        String tokenKid,
        String detail
) {
}
