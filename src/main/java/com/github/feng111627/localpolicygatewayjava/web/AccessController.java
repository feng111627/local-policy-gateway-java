package com.github.feng111627.localpolicygatewayjava.web;

import com.github.feng111627.localpolicygatewayjava.gateway.AccessResponse;
import com.github.feng111627.localpolicygatewayjava.gateway.GatewayService;
import com.github.feng111627.localpolicygatewayjava.web.dto.AccessRequestDto;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 访问判定端点：HTTP 200 仅表示判定完成，permitted 字段表示放行与否。 */
@RestController
@RequestMapping("/access")
public class AccessController {

    private final GatewayService gateway;

    public AccessController(GatewayService gateway) {
        this.gateway = gateway;
    }

    @PostMapping
    public AccessResponse decide(@RequestBody AccessRequestDto dto) {
        if (dto.getToken() == null || dto.getToken().isBlank()) {
            throw new com.github.feng111627.localpolicygatewayjava.auth.TokenVerificationException(
                    com.github.feng111627.localpolicygatewayjava.auth.VerificationFailure.MALFORMED_TOKEN,
                    "请求缺少 token");
        }
        if (dto.getResource() == null || dto.getResource().isBlank()) {
            throw new IllegalArgumentException("请求缺少 resource");
        }
        return gateway.decide(dto.getToken(), dto.getResource(),
                dto.getAction() == null ? "*" : dto.getAction(), dto.getEnv());
    }
}
