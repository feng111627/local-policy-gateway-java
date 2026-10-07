package com.github.feng111627.localpolicygatewayjava.model;

/** 本地签名密钥在轮换生命周期中的状态。 */
public enum KeyState {
    /** 当前密钥：可签发、可校验。 */
    ACTIVE,
    /** 上一代密钥：不可再签发，仅用于轮换过渡期校验。 */
    PREVIOUS,
    /** 已吊销：不可签发也不可校验，命中即拒绝。 */
    REVOKED
}
