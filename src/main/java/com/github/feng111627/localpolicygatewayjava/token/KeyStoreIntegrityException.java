package com.github.feng111627.localpolicygatewayjava.token;

import com.github.feng111627.localpolicygatewayjava.model.DenyReason;

/** 密钥库完整性被破坏（密钥材料指纹不匹配）。 */
public class KeyStoreIntegrityException extends RuntimeException {

    private final DenyReason reason;

    public KeyStoreIntegrityException(String message) {
        super(message);
        this.reason = DenyReason.KEY_TAMPERED;
    }

    public DenyReason getReason() {
        return reason;
    }
}
