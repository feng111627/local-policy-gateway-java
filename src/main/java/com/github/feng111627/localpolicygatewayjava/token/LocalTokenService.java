package com.github.feng111627.localpolicygatewayjava.token;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.feng111627.localpolicygatewayjava.model.DenyReason;
import com.github.feng111627.localpolicygatewayjava.model.KeyState;
import com.github.feng111627.localpolicygatewayjava.model.StoredKey;
import com.github.feng111627.localpolicygatewayjava.model.TokenClaims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 本地令牌签发与校验。
 *
 * <p>令牌为紧凑三段式（仅依赖 JDK Base64/HMAC，无外部 IdP）：
 * <pre>base64url(header) . base64url(claims) . base64url(HMAC-SHA256(header.claims))</pre>
 * 校验失败的每种情况都映射到独立的 {@link DenyReason}，绝不笼统拒绝。
 */
@Component
public class LocalTokenService {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String TOKEN_VERSION = "LPG1";

    private final KeyStore keyStore;
    private final Clock clock;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    public LocalTokenService(KeyStore keyStore, Clock clock) {
        this.keyStore = keyStore;
        this.clock = clock;
    }

    public String issue(String subject, List<String> roles, Duration ttl) {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("令牌主体 sub 不能为空");
        }
        if (ttl == null || ttl.isNegative() || ttl.isZero()) {
            throw new IllegalArgumentException("ttl 必须为正时长");
        }
        long now = clock.instant().getEpochSecond();
        TokenClaims claims = new TokenClaims(subject, roles == null ? List.of() : List.copyOf(roles),
                now, now + ttl.toSeconds());
        return issue(keyStore.activeKey(), claims);
    }

    public String issue(StoredKey key, TokenClaims claims) {
        if (key == null || key.state() != KeyState.ACTIVE) {
            throw new IllegalArgumentException("只能使用 ACTIVE 密钥签发令牌");
        }
        keyStore.verifyIntegrity(key);
        try {
            byte[] headerBytes = objectMapper.writeValueAsBytes(Map.of("kid", key.kid(), "ver", TOKEN_VERSION));
            byte[] claimsBytes = objectMapper.writeValueAsBytes(claims);
            String header = B64URL.encodeToString(headerBytes);
            String body = B64URL.encodeToString(claimsBytes);
            String signingInput = header + "." + body;
            byte[] signature = hmac(key, signingInput);
            return signingInput + "." + B64URL.encodeToString(signature);
        } catch (Exception e) {
            throw new IllegalStateException("令牌签发失败", e);
        }
    }

    public String activeKid() {
        return keyStore.activeKey().kid();
    }

    /**
     * 校验令牌，返回可信载荷。失败时抛出 {@link TokenVerificationException}，原因可区分：
     * MALFORMED_TOKEN / UNKNOWN_KEY / KEY_TAMPERED / KEY_REVOKED / SIGNATURE_MISMATCH / TOKEN_EXPIRED。
     */
    public TokenClaims verify(String token) {
        if (token == null || token.isBlank()) {
            throw new TokenVerificationException(DenyReason.MALFORMED_TOKEN, "令牌为空");
        }
        String compact = stripBearer(token).trim();
        String[] parts = compact.split("\\.", -1);
        if (parts.length != 3 || parts[0].isBlank() || parts[1].isBlank() || parts[2].isBlank()) {
            throw new TokenVerificationException(DenyReason.MALFORMED_TOKEN,
                    "令牌必须是 header.payload.signature 三段式结构");
        }

        Map<?, ?> header;
        TokenClaims claims;
        try {
            header = objectMapper.readValue(B64URL_DEC.decode(parts[0]), Map.class);
            claims = objectMapper.readValue(B64URL_DEC.decode(parts[1]), TokenClaims.class);
        } catch (Exception e) {
            throw new TokenVerificationException(DenyReason.MALFORMED_TOKEN, "令牌头部或载荷无法解析: " + e.getMessage());
        }

        Object kidValue = header.get("kid");
        if (!(kidValue instanceof String kid) || kid.isBlank()) {
            throw new TokenVerificationException(DenyReason.MALFORMED_TOKEN, "令牌头部缺少 kid");
        }
        if (claims.sub() == null || claims.sub().isBlank()) {
            throw new TokenVerificationException(DenyReason.MALFORMED_TOKEN, "令牌载荷缺少 sub");
        }

        StoredKey key = keyStore.find(kid).orElseThrow(() ->
                new TokenVerificationException(DenyReason.UNKNOWN_KEY, "未知签名密钥: " + kid));
        try {
            keyStore.verifyIntegrity(key);
        } catch (KeyStoreIntegrityException e) {
            throw new TokenVerificationException(e.getReason(), e.getMessage());
        }
        if (key.state() == KeyState.REVOKED) {
            throw new TokenVerificationException(DenyReason.KEY_REVOKED, "密钥 " + kid + " 已被吊销");
        }

        byte[] expectedSignature;
        byte[] providedSignature;
        try {
            expectedSignature = hmac(key, parts[0] + "." + parts[1]);
            providedSignature = B64URL_DEC.decode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw new TokenVerificationException(DenyReason.MALFORMED_TOKEN, "签名字段不是合法 Base64URL");
        }
        if (!MessageDigest.isEqual(expectedSignature, providedSignature)) {
            throw new TokenVerificationException(DenyReason.SIGNATURE_MISMATCH,
                    "令牌签名与本地密钥计算结果不一致，令牌可能被篡改");
        }

        long now = clock.instant().getEpochSecond();
        if (claims.exp() <= now) {
            throw new TokenVerificationException(DenyReason.TOKEN_EXPIRED,
                    "令牌已于 " + claims.exp() + " 过期，当前时间 " + now);
        }
        return claims;
    }

    private static String stripBearer(String authorization) {
        if (authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return authorization.substring(7);
        }
        return authorization;
    }

    private static byte[] hmac(StoredKey key, String signingInput) {
        try {
            byte[] secret = Base64.getDecoder().decode(key.secret());
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(secret, HMAC_ALGORITHM));
            return mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC 计算失败", e);
        }
    }

    /** 仅供诊断：返回令牌头部里的 kid，不做任何校验。 */
    @SuppressWarnings("unchecked")
    public Map<String, Object> peekHeader(String token) {
        try {
            String compact = stripBearer(token).trim();
            String[] parts = compact.split("\\.", -1);
            return new LinkedHashMap<>(objectMapper.readValue(B64URL_DEC.decode(parts[0]), Map.class));
        } catch (Exception e) {
            return Map.of();
        }
    }
}
