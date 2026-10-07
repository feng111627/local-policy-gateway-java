package com.github.feng111627.localpolicygatewayjava.policy;

/** 策略装载阶段可区分的错误代码。 */
public enum PolicyError {
    /** JSON 语法错误，无法解析。 */
    SYNTAX_ERROR,
    /** 缺少必填字段（policyId / version / rules / 规则核心字段等）。 */
    MISSING_FIELD,
    /** 字段取值非法（未知 effect、负数优先级、非数组等）。 */
    INVALID_VALUE,
    /** 规则 id 重复。 */
    DUPLICATE_RULE_ID,
    /** 同一优先级上存在相互矛盾的规则。 */
    CONTRADICTORY_RULES,
    /** 版本号不大于当前生效版本。 */
    STALE_VERSION
}
