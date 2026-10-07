package com.github.feng111627.localpolicygatewayjava.policy;

/** 策略加载失败异常，携带可区分的失败原因。 */
public class PolicyLoadException extends RuntimeException {
    private final PolicyLoadFailure reason;

    public PolicyLoadException(PolicyLoadFailure reason, String message) {
        super(message);
        this.reason = reason;
    }

    public PolicyLoadFailure reason() {
        return reason;
    }
}
