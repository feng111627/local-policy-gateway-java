package com.github.feng111627.localpolicygatewayjava.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * 本地令牌服务：JWT 风格的紧凑三段式 base64url 令牌，签名为 HMAC-SHA256，
 * 全部使用 JDK 内置能力，不依赖任何外部身份服务。
 *
 * <p>令牌形如 {@code header.payload.signature}：
 * header={@code {"alg":"HS256","kid":"..."}}，
 * payload={@code iss,sub,role,iat,nbf,exp}，signature=HMAC(header.payload)。
 *
 * <p>验签顺序刻意固定，使失败原因可区分：格式 → 密钥未知 → 密钥吊销 →
 * 密钥过渡期过期 → 签名不符（令牌篡改）→ 时效（nbf/exp）。
 */
public class TokenService {

    static final String ISSUER = "local-policy-gateway";

    private final KeyStore keyStore;
    private final ObjectMapper mapper = new ObjectMapper();
    private final Base64.Encoder b64url = Base64.getUrlEncoder().withoutPadding();
    private final Base64.Decoder b64urlDecoder = Base64.getUrlDecoder();

    public TokenService(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    public String issue(String subject, String role, long ttlMillis) {
        long now = System.currentTimeMillis();
        return issue(subject, role, now, ttlMillis);
    }

    /** 可注入签发时刻的重载，便于确定性测试。 */
    public String issue(String subject, String role, long issuedAtMillis, long ttlMillis) {
        try {
            SigningKey key = keyStore.activeKey();

            var header = mapper.createObjectNode();
            header.put("alg", "HS256");
            header.put("kid", key.kid());

            var payload = mapper.createObjectNode();
            payload.put("iss", ISSUER);
            payload.put("sub", subject);
            payload.put("role", role);
            payload.put("iat", issuedAtMillis);
            payload.put("nbf", issuedAtMillis);
            payload.put("exp", issuedAtMillis + ttlMillis);

            String h = encode(mapper.writeValueAsBytes(header));
            String p = encode(mapper.writeValueAsBytes(payload));
            String signingInput = h + "." + p;
            String s = encode(hmac(key, signingInput.getBytes(StandardCharsets.UTF_8)));
            return signingInput + "." + s;
        } catch (TokenVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("令牌签发失败: " + e.getMessage(), e);
        }
    }

    public Claims verify(String token) {
        return verify(token, System.currentTimeMillis());
    }

    /** 可注入“当前时间”的验签重载，便于确定性测试。 */
    public Claims verify(String token, long nowMillis) {
        if (token == null || token.isBlank()) {
            throw new TokenVerificationException(VerificationFailure.MALFORMED_TOKEN, "令牌为空");
        }
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || parts[0].isBlank() || parts[1].isBlank() || parts[2].isBlank()) {
            throw new TokenVerificationException(VerificationFailure.MALFORMED_TOKEN,
                    "令牌必须为 header.payload.signature 三段式");
        }

        JsonNode header;
        JsonNode payload;
        byte[] signature;
        try {
            header = mapper.readTree(decode(parts[0]));
            payload = mapper.readTree(decode(parts[1]));
            signature = decode(parts[2]);
        } catch (Exception e) {
            throw new TokenVerificationException(VerificationFailure.MALFORMED_TOKEN,
                    "令牌段无法解码或 JSON 损坏: " + e.getMessage());
        }

        String alg = header.path("alg").asText(null);
        String kid = header.path("kid").asText(null);
        if (!"HS256".equals(alg) || kid == null || kid.isBlank()) {
            throw new TokenVerificationException(VerificationFailure.MALFORMED_TOKEN,
                    "令牌头部缺少合法 alg/kid");
        }
        for (String claim : new String[]{"iss", "sub", "role", "iat", "nbf", "exp"}) {
            if (!payload.has(claim) || payload.get(claim).isNull()) {
                throw new TokenVerificationException(VerificationFailure.MALFORMED_TOKEN,
                        "令牌缺少必填声明: " + claim);
            }
        }
        if (!ISSUER.equals(payload.get("iss").asText())) {
            throw new TokenVerificationException(VerificationFailure.MALFORMED_TOKEN,
                    "令牌签发者不是本地签发方: " + payload.get("iss").asText());
        }

        SigningKey key = keyStore.find(kid);
        if (key == null) {
            throw new TokenVerificationException(VerificationFailure.UNKNOWN_KEY,
                    "令牌引用的签名密钥未知: kid=" + kid);
        }
        if (key.state() == KeyState.REVOKED) {
            throw new TokenVerificationException(VerificationFailure.KEY_REVOKED,
                    "签名密钥已被吊销: kid=" + kid);
        }
        if (!keyStore.isUsable(key, nowMillis)) {
            throw new TokenVerificationException(VerificationFailure.KEY_TRANSITION_EXPIRED,
                    "旧签名密钥的轮换过渡期已结束: kid=" + kid);
        }

        byte[] expected;
        try {
            expected = hmac(key, (parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new TokenVerificationException(VerificationFailure.BAD_SIGNATURE,
                    "无法计算签名: " + e.getMessage());
        }
        if (!MessageDigest.isEqual(expected, signature)) {
            throw new TokenVerificationException(VerificationFailure.BAD_SIGNATURE,
                    "签名校验失败，令牌内容可能已被篡改: kid=" + kid);
        }

        long nbf = payload.get("nbf").asLong();
        long exp = payload.get("exp").asLong();
        if (nowMillis < nbf) {
            throw new TokenVerificationException(VerificationFailure.TOKEN_NOT_YET_VALID,
                    "令牌尚未生效(nbf=" + nbf + ")");
        }
        if (nowMillis > exp) {
            throw new TokenVerificationException(VerificationFailure.TOKEN_EXPIRED,
                    "令牌已过期(exp=" + exp + ")");
        }

        return new Claims(payload.get("iss").asText(), payload.get("sub").asText(),
                payload.get("role").asText(), payload.get("iat").asLong(),
                nbf, exp, kid);
    }

    private byte[] hmac(SigningKey key, byte[] data) throws Exception {
        if (key.algorithm() != KeyAlgorithm.HMAC_SHA256) {
            throw new IllegalArgumentException("不支持的算法: " + key.algorithm());
        }
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key.secret(), "HmacSHA256"));
        return mac.doFinal(data);
    }

    private String encode(byte[] b) {
        return b64url.encodeToString(b);
    }

    private byte[] decode(String s) {
        return b64urlDecoder.decode(s);
    }

    /** 令牌声明。 */
    public record Claims(
            String iss,
            String sub,
            String role,
            long iat,
            long nbf,
            long exp,
            String kid
    ) {
    }
}
