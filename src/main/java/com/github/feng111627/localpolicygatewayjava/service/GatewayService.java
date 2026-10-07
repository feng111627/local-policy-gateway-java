package com.github.feng111627.localpolicygatewayjava.service;

import com.github.feng111627.localpolicygatewayjava.audit.AuditEvent;
import com.github.feng111627.localpolicygatewayjava.audit.AuditLog;
import com.github.feng111627.localpolicygatewayjava.model.Decision;
import com.github.feng111627.localpolicygatewayjava.model.DecisionRequest;
import com.github.feng111627.localpolicygatewayjava.model.DecisionResponse;
import com.github.feng111627.localpolicygatewayjava.model.DenyReason;
import com.github.feng111627.localpolicygatewayjava.model.KeyRotationResult;
import com.github.feng111627.localpolicygatewayjava.model.Policy;
import com.github.feng111627.localpolicygatewayjava.model.PolicyUpdateResult;
import com.github.feng111627.localpolicygatewayjava.model.TokenClaims;
import com.github.feng111627.localpolicygatewayjava.policy.Evaluation;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyEngine;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyParseException;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyParser;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyRepository;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyValidator;
import com.github.feng111627.localpolicygatewayjava.token.KeyStoreIntegrityException;
import com.github.feng111627.localpolicygatewayjava.token.KeyStore;
import com.github.feng111627.localpolicygatewayjava.token.LocalTokenService;
import com.github.feng111627.localpolicygatewayjava.token.TokenVerificationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;

/**
 * 访问决策总入口。
 *
 * <p>判定顺序：令牌校验（失败即按可区分原因拒绝）→ 策略引擎求值 → 追加审计记录。
 * 策略热更新先解析、再校验、最后原子替换：任一步失败都返回失败结果且保留上一版策略。
 */
@Service
public class GatewayService {

    private final LocalTokenService tokenService;
    private final PolicyEngine engine;
    private final PolicyRepository repository;
    private final PolicyParser parser;
    private final PolicyValidator validator;
    private final KeyStore keyStore;
    private final AuditLog auditLog;

    @Autowired
    public GatewayService(LocalTokenService tokenService, PolicyEngine engine,
                          PolicyRepository repository, PolicyParser parser,
                          PolicyValidator validator, KeyStore keyStore,
                          AuditLog auditLog) {
        this.tokenService = tokenService;
        this.engine = engine;
        this.repository = repository;
        this.parser = parser;
        this.validator = validator;
        this.keyStore = keyStore;
        this.auditLog = auditLog;
    }

    public DecisionResponse decide(String authorizationHeader, DecisionRequest request) {
        String resource = request == null ? null : request.resource();

        TokenClaims claims;
        String kid = null;
        // 令牌阶段尚未依赖策略；失败时记录当前最新版本号（仅作上下文，不参与任何放行判定）
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            return tokenRejected(resource, kid,
                    new TokenVerificationException(DenyReason.NO_TOKEN, "请求未携带 Authorization 令牌"));
        }
        try {
            claims = tokenService.verify(authorizationHeader);
            kid = String.valueOf(tokenService.peekHeader(authorizationHeader).getOrDefault("kid", "unknown"));
        } catch (TokenVerificationException | KeyStoreIntegrityException e) {
            return tokenRejected(resource, kid, e);
        }

        // 关键：在令牌可信之后、策略求值之前抓取唯一一次策略快照，
        // 求值、响应版本号与审计全部使用这同一个不可变快照，杜绝跨版本拼装。
        Policy snapshot = repository.current();
        String policyId = snapshot == null ? null : snapshot.policyId();
        long policyVersion = snapshot == null ? -1 : snapshot.version();
        Evaluation evaluation = engine.evaluate(snapshot, claims, request);
        DecisionResponse response;
        if (evaluation.decision() == Decision.ALLOW) {
            response = new DecisionResponse(Decision.ALLOW, evaluation.message(), evaluation.matchedRuleId(),
                    policyId, policyVersion, claims.sub());
        } else {
            response = deny(evaluation.denyReason(), evaluation.message(), policyId, policyVersion,
                    evaluation.matchedRuleId(), claims.sub(), kid);
        }
        audit(resource, claims.sub(), response, kid, evaluation.message());
        return response;
    }

    private DecisionResponse deny(DenyReason reason, String message, String policyId, long version,
                                  String matchedRuleId, String subject, String kid) {
        return new DecisionResponse(Decision.DENY, "[" + reason.name() + "] " + message,
                matchedRuleId, policyId, version, subject);
    }

    private void audit(String resource, String subject, DecisionResponse response, String kid, String detail) {
        DenyReason denyReason = response.decision() == Decision.DENY
                ? extractReason(response.reason())
                : null;
        auditLog.record(new AuditEvent(Instant.now(), subject, resource, response.decision(),
                denyReason, response.matchedRuleId(), response.policyId(), response.policyVersion(),
                kid, detail));
    }

    private DenyReason extractReason(String prefixed) {
        if (prefixed != null && prefixed.startsWith("[") && prefixed.contains("]")) {
            try {
                return DenyReason.valueOf(prefixed.substring(1, prefixed.indexOf(']')));
            } catch (IllegalArgumentException ignored) {
                // 落到未知原因兜底
            }
        }
        return null;
    }

    private DecisionResponse tokenRejected(String resource, String kid, RuntimeException error) {
        DenyReason reason = error instanceof TokenVerificationException tve
                ? tve.getReason()
                : ((KeyStoreIntegrityException) error).getReason();
        Policy snapshot = repository.current();
        String policyId = snapshot == null ? null : snapshot.policyId();
        long policyVersion = snapshot == null ? -1 : snapshot.version();
        DecisionResponse response = deny(reason, error.getMessage(), policyId, policyVersion, null, null, kid);
        audit(resource, null, response, kid, error.getMessage());
        return response;
    }

    /**
     * 热更新策略：解析 → 校验 → 原子替换。失败返回带错误代码的结果，当前策略不受影响。
     */
    public PolicyUpdateResult reloadPolicy(String json) {
        long activeVersion = repository.isEmpty() ? 0 : repository.current().version();
        try {
            Policy candidate = parser.parse(json);
            validator.validate(candidate);
            return repository.replace(candidate);
        } catch (PolicyParseException e) {
            return new PolicyUpdateResult(false, activeVersion, e.getErrorCode().name(),
                    "策略更新未生效，保留 v" + activeVersion + "：" + e.getMessage());
        }
    }

    /** 与 reloadPolicy 等价，但请求体可能是 {"json": "..."} 包装或原始 JSON 字符串。 */
    public PolicyUpdateResult reloadPolicyFromBody(Map<String, Object> body) {
        Object json = body.get("json");
        if (json == null) {
            json = body.get("policy");
        }
        if (!(json instanceof String text)) {
            long activeVersion = repository.isEmpty() ? 0 : repository.current().version();
            return new PolicyUpdateResult(false, activeVersion, "MISSING_FIELD",
                    "更新请求需要在 json 或 policy 字段中提供策略文本");
        }
        return reloadPolicy(text);
    }

    public KeyRotationResult rotateKeys() {
        return keyStore.rotate();
    }
}
