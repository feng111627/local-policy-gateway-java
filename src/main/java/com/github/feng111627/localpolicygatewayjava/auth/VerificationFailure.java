package com.github.feng111627.localpolicygatewayjava.auth;

/** 令牌/密钥校验失败的可区分原因。 */
public enum VerificationFailure {
    /** 令牌格式非法：不是三段式、base64url 无法解码、JSON 损坏或缺少必填声明。 */
    MALFORMED_TOKEN,
    /** 令牌头部引用的 kid 在本地密钥库中不存在。 */
    UNKNOWN_KEY,
    /** 引用的密钥已被显式吊销。 */
    KEY_REVOKED,
    /** 旧密钥的轮换过渡期已结束，其签发的令牌不再可用。 */
    KEY_TRANSITION_EXPIRED,
    /** 签名与内容不符：令牌被篡改。 */
    BAD_SIGNATURE,
    /** 令牌已过 exp。 */
    TOKEN_EXPIRED,
    /** 令牌尚未到 nbf。 */
    TOKEN_NOT_YET_VALID,
    /** 密钥库文件校验和不匹配：密钥被篡改。 */
    KEYSTORE_TAMPERED,
    /** 密钥库文件不存在且无法引导。 */
    KEYSTORE_MISSING
}
