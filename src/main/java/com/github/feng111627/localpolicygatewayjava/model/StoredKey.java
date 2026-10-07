package com.github.feng111627.localpolicygatewayjava.model;

/**
 * 密钥库中的一把本地签名密钥。
 *
 * @param kid          密钥标识
 * @param secret       Base64 编码的 HMAC 密钥材料
 * @param state        ACTIVE / PREVIOUS / REVOKED
 * @param issuedAt     创建时间（epoch 秒）
 * @param fingerprint  密钥材料完整性指纹（防篡改）
 */
public record StoredKey(
        String kid,
        String secret,
        KeyState state,
        long issuedAt,
        String fingerprint
) {
}
