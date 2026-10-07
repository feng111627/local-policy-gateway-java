package com.github.feng111627.localpolicygatewayjava.policy;

/** 策略加载失败的可区分原因。 */
public enum PolicyLoadFailure {
    SYNTAX_ERROR,
    MISSING_FIELD,
    INVALID_VALUE,
    DUPLICATE_RULE_ID,
    CONTRADICTION
}
