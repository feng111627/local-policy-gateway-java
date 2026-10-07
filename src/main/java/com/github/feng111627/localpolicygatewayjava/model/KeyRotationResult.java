package com.github.feng111627.localpolicygatewayjava.model;

/**
 * 一次密钥轮换的结果。
 *
 * @param success    是否成功
 * @param activeKid  轮换后当前密钥 id
 * @param previousKid 轮换过渡期内仍可校验的旧密钥 id；没有时为 null
 * @param message    说明
 */
public record KeyRotationResult(
        boolean success,
        String activeKid,
        String previousKid,
        String message
) {
}
