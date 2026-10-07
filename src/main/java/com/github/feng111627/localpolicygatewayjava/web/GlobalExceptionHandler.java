package com.github.feng111627.localpolicygatewayjava.web;

import com.github.feng111627.localpolicygatewayjava.auth.TokenVerificationException;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyLoadException;
import com.github.feng111627.localpolicygatewayjava.web.dto.ErrorDto;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.UUID;

/** 把校验/加载失败翻译成带可区分 reason 码的错误响应，绝不静默吞掉。 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(TokenVerificationException.class)
    public ResponseEntity<ErrorDto> handleToken(TokenVerificationException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ErrorDto("TOKEN_VERIFICATION_FAILED", e.reason().name(),
                        UUID.randomUUID().toString()));
    }

    @ExceptionHandler(PolicyLoadException.class)
    public ResponseEntity<ErrorDto> handlePolicy(PolicyLoadException e) {
        return ResponseEntity.badRequest()
                .body(new ErrorDto("POLICY_LOAD_REJECTED", e.reason().name(),
                        UUID.randomUUID().toString()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorDto> handleUnreadable(HttpMessageNotReadableException e) {
        return ResponseEntity.badRequest()
                .body(new ErrorDto("BAD_REQUEST", "MALFORMED_REQUEST_BODY",
                        UUID.randomUUID().toString()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorDto> handleIllegal(IllegalArgumentException e) {
        return ResponseEntity.badRequest()
                .body(new ErrorDto("BAD_REQUEST", e.getMessage(),
                        UUID.randomUUID().toString()));
    }
}
