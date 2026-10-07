package com.github.feng111627.localpolicygatewayjava.model;

import java.util.List;

/**
 * 本地令牌载荷。
 *
 * @param sub  主体
 * @param roles 角色列表
 * @param iat  签发时间（epoch 秒）
 * @param exp  过期时间（epoch 秒）
 */
public record TokenClaims(
        String sub,
        List<String> roles,
        long iat,
        long exp
) {
}
