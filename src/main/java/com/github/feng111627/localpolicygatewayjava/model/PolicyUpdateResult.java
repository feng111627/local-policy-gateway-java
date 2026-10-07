package com.github.feng111627.localpolicygatewayjava.model;

/**
 * 策略热更新结果：成功时新版本整体生效；失败时上一版完整保留。
 *
 * @param success       是否生效
 * @param activeVersion 当前仍生效的策略版本（失败时即上一版）
 * @param errorCode     失败原因代码；成功时为 null
 * @param message       说明
 */
public record PolicyUpdateResult(
        boolean success,
        long activeVersion,
        String errorCode,
        String message
) {
}
