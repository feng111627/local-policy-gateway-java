package com.github.feng111627.localpolicygatewayjava.auth;

/** 本地签名密钥材料与元数据。 */
public record SigningKey(
        String kid,
        KeyAlgorithm algorithm,
        byte[] secret,
        KeyState state,
        long createdAtEpochMillis,
        long retireAtEpochMillis
) {
}
