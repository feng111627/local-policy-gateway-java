package com.github.feng111627.localpolicygatewayjava.policy;

import com.github.feng111627.localpolicygatewayjava.model.Decision;
import com.github.feng111627.localpolicygatewayjava.model.DenyReason;

/**
 * 策略引擎对一次请求的求值结果。
 *
 * @param decision      ALLOW / DENY
 * @param matchedRuleId 命中规则 id；无命中时为 null
 * @param denyReason    拒绝时的可区分原因；放行时为 null
 * @param message       可解释的人读说明
 */
public record Evaluation(
        Decision decision,
        String matchedRuleId,
        DenyReason denyReason,
        String message
) {

    public static Evaluation allow(String ruleId, String message) {
        return new Evaluation(Decision.ALLOW, ruleId, null, message);
    }

    public static Evaluation deny(String ruleId, DenyReason reason, String message) {
        return new Evaluation(Decision.DENY, ruleId, reason, message);
    }
}
