package com.github.feng111627.localpolicygatewayjava.web.dto;

/** 密钥轮换结果。 */
public record KeyRotationResultDto(String newKid, String previousKid, String status) {
}
