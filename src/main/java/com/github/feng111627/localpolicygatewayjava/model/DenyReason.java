package com.github.feng111627.localpolicygatewayjava.model;

/**
 * 可区分的拒绝原因。每一个原因都对应一条明确、可向调用方解释的拒绝语义，
 * 既不允许“静默跳过”，也不允许把不同故障混为一个笼统拒绝。
 */
public enum DenyReason {
    /** 请求未携带令牌。 */
    NO_TOKEN,
    /** 令牌格式不合法（不是三段式结构或 Base64/JSON 无法解析）。 */
    MALFORMED_TOKEN,
    /** 令牌签名与本地密钥计算结果不一致（令牌可能被篡改）。 */
    SIGNATURE_MISMATCH,
    /** 令牌头部 kid 在本地密钥库中不存在。 */
    UNKNOWN_KEY,
    /** 令牌已过期（exp &lt; 当前时间）。 */
    TOKEN_EXPIRED,
    /** 签发该令牌的密钥已被吊销。 */
    KEY_REVOKED,
    /** 本地密钥材料的完整性指纹不匹配（密钥文件被篡改）。 */
    KEY_TAMPERED,
    /** 没有任何策略规则匹配该请求，按默认拒绝处理。 */
    NO_MATCHING_RULE,
    /** 命中的最高优先级规则显式要求 DENY。 */
    EXPLICITLY_DENIED,
    /** 同一优先级上存在相互矛盾的 allow/deny 规则。 */
    CONTRADICTORY_RULES,
    /** 当前生效策略无法用于判定（防御性拒绝，正常热更新流程不会出现）。 */
    POLICY_UNAVAILABLE
}
