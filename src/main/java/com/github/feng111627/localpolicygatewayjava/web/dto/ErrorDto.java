package com.github.feng111627.localpolicygatewayjava.web.dto;

/** 统一错误体。 */
public record ErrorDto(String error, String reason, String requestId) {
}
