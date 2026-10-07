package com.github.feng111627.localpolicygatewayjava.auth;

/** 令牌校验失败异常，携带可区分原因。 */
public class TokenVerificationException extends RuntimeException {
    private final VerificationFailure reason;

    public TokenVerificationException(VerificationFailure reason, String message) {
        super(message);
        this.reason = reason;
    }

    public VerificationFailure reason() {
        return reason;
    }
}
