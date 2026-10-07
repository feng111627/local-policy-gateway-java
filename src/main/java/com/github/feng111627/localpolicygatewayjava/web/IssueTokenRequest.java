package com.github.feng111627.localpolicygatewayjava.web;

import java.util.List;

/** 本地辅助签发令牌的请求体。 */
public record IssueTokenRequest(
        String sub,
        List<String> roles,
        Long ttlSeconds
) {
}
