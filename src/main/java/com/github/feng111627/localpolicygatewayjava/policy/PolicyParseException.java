package com.github.feng111627.localpolicygatewayjava.policy;

/** 策略解析或校验失败，必须携带可区分的 {@link PolicyError} 与具体说明。 */
public class PolicyParseException extends RuntimeException {

    private final PolicyError errorCode;

    public PolicyParseException(PolicyError errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public PolicyError getErrorCode() {
        return errorCode;
    }
}
