package com.github.feng111627.localpolicygatewayjava.web;

import com.github.feng111627.localpolicygatewayjava.auth.KeyStore;
import com.github.feng111627.localpolicygatewayjava.auth.TokenService;
import com.github.feng111627.localpolicygatewayjava.config.GatewayProperties;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyAdminService;
import com.github.feng111627.localpolicygatewayjava.web.dto.IssueTokenDto;
import com.github.feng111627.localpolicygatewayjava.web.dto.IssuedTokenDto;
import com.github.feng111627.localpolicygatewayjava.web.dto.KeyRotationResultDto;
import com.github.feng111627.localpolicygatewayjava.web.dto.PolicyUpdateResultDto;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Path;

/**
 * 管理端点（本地演示用，无网络鉴权依赖）：
 * 策略整版热更新、密钥轮换（带过渡期）、密钥吊销。
 */
@RestController
@RequestMapping("/admin")
public class AdminController {

    private final PolicyAdminService policyAdmin;
    private final KeyStore keyStore;
    private final TokenService tokenService;
    private final GatewayProperties props;

    public AdminController(PolicyAdminService policyAdmin, KeyStore keyStore,
                           TokenService tokenService, GatewayProperties props) {
        this.policyAdmin = policyAdmin;
        this.keyStore = keyStore;
        this.tokenService = tokenService;
        this.props = props;
    }

    /**
     * 仅用于本地演示：用当前 ACTIVE 密钥签发令牌。
     * 真实部署应替换为受控的内部签发流程；本服务本身不依赖任何外部身份服务。
     */
    @PostMapping("/tokens/issue")
    public IssuedTokenDto issueToken(@RequestBody IssueTokenDto req) {
        if (req.getSubject() == null || req.getSubject().isBlank()
                || req.getRole() == null || req.getRole().isBlank()) {
            throw new IllegalArgumentException("subject 与 role 均必填");
        }
        long ttl = req.getTtlMillis() <= 0 ? 3_600_000L : req.getTtlMillis();
        String token = tokenService.issue(req.getSubject(), req.getRole(), ttl);
        return new IssuedTokenDto(token, keyStore.activeKey().kid(),
                req.getSubject(), req.getRole(), ttl);
    }

    /** 请求体为完整策略 JSON；非法则整体不生效并返回可区分原因。 */
    @PostMapping(path = "/policies",
            consumes = {MediaType.APPLICATION_JSON_VALUE, MediaType.TEXT_PLAIN_VALUE})
    public PolicyUpdateResultDto updatePolicy(@RequestBody String body) {
        PolicyAdminService.UpdateResult r = policyAdmin.apply(body);
        if (r.applied()) {
            try {
                Path policyPath = java.nio.file.Paths.get(props.getPolicyFile());
                java.nio.file.Files.createDirectories(policyPath.toAbsolutePath().getParent());
                java.nio.file.Files.writeString(policyPath, body,
                        java.nio.charset.StandardCharsets.UTF_8);
            } catch (Exception e) {
                // 内存版本已生效；持久化失败只提示，不回滚判定语义
                return new PolicyUpdateResultDto(true, r.version(), null,
                        r.detail() + "（注意：策略文件持久化失败: " + e.getMessage() + "）");
            }
        }
        return new PolicyUpdateResultDto(r.applied(), r.version(), r.reason(), r.detail());
    }

    @PostMapping("/keys/rotate")
    public KeyRotationResultDto rotate() {
        String previous = keyStore.activeKey().kid();
        String newKid = "k-" + Long.toHexString(System.currentTimeMillis());
        keyStore.rotate(newKid, System.currentTimeMillis(), props.getRotationOverlapMillis());
        return new KeyRotationResultDto(newKid, previous,
                "ROTATED: 旧密钥 " + previous + " 在 "
                        + props.getRotationOverlapMillis() + "ms 过渡期内仍可验签");
    }

    @PostMapping("/keys/revoke")
    public KeyRotationResultDto revoke(@RequestBody String kid) {
        keyStore.revoke(kid);
        return new KeyRotationResultDto(null, kid, "REVOKED");
    }
}
