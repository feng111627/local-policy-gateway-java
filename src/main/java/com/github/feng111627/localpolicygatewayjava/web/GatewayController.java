package com.github.feng111627.localpolicygatewayjava.web;

import com.github.feng111627.localpolicygatewayjava.audit.AuditEvent;
import com.github.feng111627.localpolicygatewayjava.audit.AuditLog;
import com.github.feng111627.localpolicygatewayjava.model.DecisionRequest;
import com.github.feng111627.localpolicygatewayjava.model.DecisionResponse;
import com.github.feng111627.localpolicygatewayjava.model.KeyRotationResult;
import com.github.feng111627.localpolicygatewayjava.model.PolicyUpdateResult;
import com.github.feng111627.localpolicygatewayjava.service.GatewayService;
import com.github.feng111627.localpolicygatewayjava.token.LocalTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * 本地访问决策服务的 HTTP 入口。仅面向本机/受信网络，不依赖任何外部鉴权服务。
 */
@RestController
@RequestMapping("/local-gateway")
public class GatewayController {

    private final GatewayService gatewayService;
    private final LocalTokenService tokenService;
    private final AuditLog auditLog;

    @Autowired
    public GatewayController(GatewayService gatewayService, LocalTokenService tokenService, AuditLog auditLog) {
        this.gatewayService = gatewayService;
        this.tokenService = tokenService;
        this.auditLog = auditLog;
    }

    @PostMapping("/decide")
    public ResponseEntity<DecisionResponse> decide(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @RequestBody DecisionRequest request) {
        DecisionResponse response = gatewayService.decide(authorization, request);
        return switch (response.decision()) {
            case ALLOW -> ResponseEntity.ok(response);
            case DENY -> ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
        };
    }

    @PostMapping("/admin/policies/reload")
    public PolicyUpdateResult reload(@RequestBody Map<String, Object> body) {
        return gatewayService.reloadPolicyFromBody(body);
    }

    @PostMapping("/admin/keys/rotate")
    public KeyRotationResult rotate() {
        return gatewayService.rotateKeys();
    }

    @GetMapping("/admin/audit")
    public List<AuditEvent> audit() {
        return auditLog.events();
    }

    /** 本地辅助端点：用当前 ACTIVE 密钥签发测试令牌，不连接任何外部 IdP。 */
    @PostMapping("/tokens")
    public Map<String, String> issueToken(@RequestBody IssueTokenRequest request) {
        if (request == null || request.sub() == null || request.sub().isBlank()) {
            throw new IllegalArgumentException("sub 不能为空");
        }
        long ttl = request.ttlSeconds() == null ? 3600 : request.ttlSeconds();
        String token = tokenService.issue(request.sub(), request.roles(), Duration.ofSeconds(ttl));
        return Map.of("token", token, "kid", tokenService.activeKid());
    }
}
