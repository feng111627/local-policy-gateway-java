package com.github.feng111627.localpolicygatewayjava.model;

import java.util.List;
import java.util.Map;

/**
 * 一条访问策略规则。
 *
 * @param id        规则唯一标识，用于审计与解释命中来源
 * @param effect    命中后的效果：ALLOW / DENY
 * @param priority  优先级，数值越大越优先；同优先级上的 allow/deny 冲突属于矛盾规则
 * @param roles     命中所需角色（任一匹配即可），为空表示不限制角色
 * @param resources 资源匹配模式（精确匹配或 {@code *} 单段通配），为空表示不限制资源
 * @param env       环境属性约束：键必须存在，且请求值落在候选值列表中
 */
public record Rule(
        String id,
        Decision effect,
        int priority,
        List<String> roles,
        List<String> resources,
        Map<String, List<String>> env
) {
}
