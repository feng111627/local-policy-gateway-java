package com.github.feng111627.localpolicygatewayjava.token;

import com.github.feng111627.localpolicygatewayjava.model.DenyReason;

/** 令牌校验失败，必须映射到一个可区分的 {@link DenyReason}。 */
public class TokenVerificationException extends RuntimeException {

    private final DenyReason reason;

    public TokenVerificationException(DenyReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public DenyReason getReason() {
        return reason;
    }
}
