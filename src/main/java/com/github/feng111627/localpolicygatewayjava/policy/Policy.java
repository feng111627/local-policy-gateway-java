package com.github.feng111627.localpolicygatewayjava.policy;

import java.util.List;

/** 一版完整策略：整体生效或整体不生效。 */
public record Policy(String version, List<Rule> rules) {
}
