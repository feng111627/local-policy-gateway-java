package com.github.feng111627.localpolicygatewayjava.policy;

/** 访问被拒绝的可区分原因。 */
public enum DenyReason {
    NO_POLICY_LOADED,
    NO_RULE_MATCHED,
    EXPLICIT_DENY
}
