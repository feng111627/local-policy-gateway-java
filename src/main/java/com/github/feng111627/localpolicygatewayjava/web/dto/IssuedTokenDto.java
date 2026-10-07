package com.github.feng111627.localpolicygatewayjava.web.dto;

/** 本地演示用令牌签发响应。 */
public record IssuedTokenDto(String token, String kid, String subject, String role, long ttlMillis) {
}
