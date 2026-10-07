package com.github.feng111627.localpolicygatewayjava.auth;

/** 密钥状态：当前主用 / 轮换过渡旧密钥 / 已吊销。 */
public enum KeyState {
    ACTIVE,
    RETIRED,
    REVOKED
}
