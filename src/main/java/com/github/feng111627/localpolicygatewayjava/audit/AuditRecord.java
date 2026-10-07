package com.github.feng111627.localpolicygatewayjava.audit;

/** 单次判定留下的可追溯审计记录。 */
public record AuditRecord(
        long timestampEpochMillis,
        String requestId,
        String subject,
        String role,
        String resource,
        String action,
        AuditOutcome outcome,
        String reasonCode,
        String matchedRuleId,
        String policyVersion,
        String kid
) {
}
