package com.github.feng111627.localpolicygatewayjava.gateway;

import com.github.feng111627.localpolicygatewayjava.audit.AuditOutcome;
import com.github.feng111627.localpolicygatewayjava.audit.AuditRecord;
import com.github.feng111627.localpolicygatewayjava.audit.AuditService;
import com.github.feng111627.localpolicygatewayjava.auth.KeyStore;
import com.github.feng111627.localpolicygatewayjava.auth.TokenService;
import com.github.feng111627.localpolicygatewayjava.auth.TokenVerificationException;
import com.github.feng111627.localpolicygatewayjava.policy.AccessRequest;
import com.github.feng111627.localpolicygatewayjava.policy.Decision;
import com.github.feng111627.localpolicygatewayjava.policy.Policy;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyEngine;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;

/**
 * 网关编排：
 * 先做本地令牌校验（失败即拒绝并按原因留痕），再以令牌中的角色 + 请求资源/动作/环境
 * 做策略判定，最后无论放行拒绝都写一条审计记录。
 */
@Service
public class GatewayService {

    private final TokenService tokenService;
    private final KeyStore keyStore;
    private final PolicyEngine engine;
    private final AuditService audit;

    public GatewayService(TokenService tokenService, KeyStore keyStore,
                          PolicyEngine engine, AuditService audit) {
        this.tokenService = tokenService;
        this.keyStore = keyStore;
        this.engine = engine;
        this.audit = audit;
    }

    public AccessResponse decide(String token, String resource, String action, Map<String, String> env) {
        String requestId = UUID.randomUUID().toString();
        long now = System.currentTimeMillis();

        com.github.feng111627.localpolicygatewayjava.auth.TokenService.Claims claims;
        try {
            claims = tokenService.verify(token);
        } catch (TokenVerificationException e) {
            audit.record(new AuditRecord(now, requestId, "-", "-",
                    resource, action, AuditOutcome.TOKEN_INVALID,
                    e.reason().name(), null, currentVersion(),
                    extractKidQuietly(token)));
            return new AccessResponse(false, e.reason().name(), null, currentVersion(), requestId);
        }

        Decision d = engine.evaluate(new AccessRequest(
                claims.role(), resource, action == null ? "*" : action,
                env == null ? Map.of() : env));

        AuditOutcome outcome = d.permitted() ? AuditOutcome.PERMIT : AuditOutcome.DENY;
        String reasonCode = d.permitted() ? "PERMIT"
                : (d.denyReason() == null ? "DENY" : d.denyReason().name());
        audit.record(new AuditRecord(now, requestId, claims.sub(), claims.role(),
                resource, action, outcome, reasonCode, d.matchedRuleId(),
                d.policyVersion(), claims.kid()));

        return new AccessResponse(d.permitted(), reasonCode, d.matchedRuleId(),
                d.policyVersion(), requestId);
    }

    private String currentVersion() {
        Policy p = engine.current();
        return p == null ? null : p.version();
    }

    private String extractKidQuietly(String token) {
        if (token == null) {
            return null;
        }
        try {
            return tokenService.verify(token).kid();
        } catch (RuntimeException e) {
            // 非法令牌无法可靠解析 kid，审计中记 unknown
            return "unknown";
        }
    }
}
