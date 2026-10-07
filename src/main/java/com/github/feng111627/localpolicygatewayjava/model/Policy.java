package com.github.feng111627.localpolicygatewayjava.model;

import java.util.List;

/**
 * 一份完整策略。策略以整体为单位生效：要么整份可用，要么整份被拒绝。
 *
 * @param policyId 策略标识
 * @param name     策略名称
 * @param version  单调递增的策略版本号
 * @param rules    规则集合
 */
public record Policy(
        String policyId,
        String name,
        long version,
        List<Rule> rules
) {
}
