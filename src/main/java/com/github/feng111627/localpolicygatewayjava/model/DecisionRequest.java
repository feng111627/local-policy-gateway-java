package com.github.feng111627.localpolicygatewayjava.model;

import java.util.Map;

/**
 * 访问判定请求。
 *
 * @param resource 目标资源标识
 * @param env      请求侧环境属性（如 env=prod、ip 等），与规则 env 约束做匹配
 */
public record DecisionRequest(
        String resource,
        Map<String, String> env
) {
}
