package com.github.feng111627.localpolicygatewayjava.policy;

import java.util.Map;

/** 待判定的访问请求：角色 + 资源 + 动作 + 环境属性。 */
public record AccessRequest(
        String role,
        String resource,
        String action,
        Map<String, String> env
) {
}
