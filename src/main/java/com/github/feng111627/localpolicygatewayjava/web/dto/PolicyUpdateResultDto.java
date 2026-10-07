package com.github.feng111627.localpolicygatewayjava.web.dto;

/** 热更新结果。 */
public record PolicyUpdateResultDto(boolean applied, String version, String reason, String detail) {
}
