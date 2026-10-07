package com.github.feng111627.localpolicygatewayjava.tests;

import com.github.feng111627.localpolicygatewayjava.auth.KeyStore;
import com.github.feng111627.localpolicygatewayjava.auth.TokenService;
import com.github.feng111627.localpolicygatewayjava.auth.TokenVerificationException;
import com.github.feng111627.localpolicygatewayjava.auth.VerificationFailure;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** 令牌签发/校验主线：放行校验 + 各类拒绝原因可区分 + 轮换过渡语义。 */
class TokenServiceTest {

    @TempDir
    Path dir;

    private KeyStore keyStore;
    private TokenService tokens;
    private long now;

    @BeforeEach
    void setUp() {
        keyStore = new KeyStore(dir.resolve("keystore.json"));
        keyStore.load();
        tokens = new TokenService(keyStore);
        now = 10_000_000_000L;
    }

    @Nested
    @DisplayName("正常校验")
    class Happy {

        @Test
        @DisplayName("本地签发的令牌可通过校验并取回角色")
        void roundTrip() {
            String t = tokens.issue("user-1", "reader", now, 60_000L);
            TokenService.Claims c = tokens.verify(t, now + 1_000L);
            assertEquals("user-1", c.sub());
            assertEquals("reader", c.role());
            assertEquals(keyStore.activeKey().kid(), c.kid());
        }
    }

    @Nested
    @DisplayName("拒绝原因可区分")
    class Failures {

        @Test
        @DisplayName("格式损坏 -> MALFORMED_TOKEN")
        void malformed() {
            assertReason("not-a-token", VerificationFailure.MALFORMED_TOKEN, now);
        }

        @Test
        @DisplayName("kid 未知 -> UNKNOWN_KEY")
        void unknownKey() {
            String crafted = craftToken("k-ghost", now);
            TokenVerificationException e = assertThrows(TokenVerificationException.class,
                    () -> tokens.verify(crafted, now));
            assertEquals(VerificationFailure.UNKNOWN_KEY, e.reason());
        }

        @Test
        @DisplayName("篡改 payload(改角色) -> BAD_SIGNATURE")
        void tamperedPayload() {
            String t = tokens.issue("u", "reader", now, 60_000L);
            String[] parts = t.split("\\.");
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            String tamperedPayload = payload.replace("reader", "admin");
            parts[1] = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(tamperedPayload.getBytes());
            String tampered = String.join(".", parts);
            assertEquals(VerificationFailure.BAD_SIGNATURE,
                    assertThrows(TokenVerificationException.class,
                            () -> tokens.verify(tampered, now)).reason());
        }

        @Test
        @DisplayName("过期 -> TOKEN_EXPIRED")
        void expired() {
            String t = tokens.issue("u", "reader", now, 1_000L);
            assertReason(t, VerificationFailure.TOKEN_EXPIRED, now + 1_001L);
        }

        @Test
        @DisplayName("未到生效时间 -> TOKEN_NOT_YET_VALID")
        void notBefore() {
            String t = tokens.issue("u", "reader", now, 60_000L);
            assertReason(t, VerificationFailure.TOKEN_NOT_YET_VALID, now - 1L);
        }

        @Test
        @DisplayName("密钥吊销 -> KEY_REVOKED")
        void revokedKey() {
            String kid = keyStore.activeKey().kid();
            String t = tokens.issue("u", "reader", now, 60_000L);
            keyStore.revoke(kid);
            assertReason(t, VerificationFailure.KEY_REVOKED, now);
        }
    }

    @Nested
    @DisplayName("密钥轮换过渡语义")
    class Rotation {

        @Test
        @DisplayName("过渡期内旧密钥令牌仍可用，新签发的令牌用新密钥")
        void oldTokenValidDuringOverlap() {
            String oldKid = keyStore.activeKey().kid();
            String oldToken = tokens.issue("u", "reader", now, 60_000L);

            keyStore.rotate("k-new", now, 30_000L);
            String newToken = tokens.issue("u", "reader", now, 60_000L);

            assertEquals(oldKid, tokens.verify(oldToken, now + 10_000L).kid());
            assertEquals("k-new", tokens.verify(newToken, now + 10_000L).kid());
        }

        @Test
        @DisplayName("过渡期结束后旧密钥令牌被拒 -> KEY_TRANSITION_EXPIRED")
        void oldTokenRejectedAfterOverlap() {
            String oldToken = tokens.issue("u", "reader", now, 60_000L);
            keyStore.rotate("k-new", now, 30_000L);
            assertReason(oldToken, VerificationFailure.KEY_TRANSITION_EXPIRED,
                    now + 30_001L);
        }

        @Test
        @DisplayName("过渡期内旧密钥被吊销 -> KEY_REVOKED 优先于过渡过期")
        void revokeOldDuringOverlap() {
            String oldKid = keyStore.activeKey().kid();
            String oldToken = tokens.issue("u", "reader", now, 60_000L);
            keyStore.rotate("k-new", now, 30_000L);
            keyStore.revoke(oldKid);
            assertReason(oldToken, VerificationFailure.KEY_REVOKED, now + 29_000L);
        }
    }

    private void assertReason(String token, VerificationFailure expected, long at) {
        TokenVerificationException e = assertThrows(TokenVerificationException.class,
                () -> tokens.verify(token, at));
        assertEquals(expected, e.reason());
    }

    /** 用一把“不存在的 kid”构造合法签名结构，触发 UNKNOWN_KEY 路径。 */
    private String craftToken(String ghostKid, long at) {
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(("{\"alg\":\"HS256\",\"kid\":\"" + ghostKid + "\"}")
                        .getBytes());
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(("{\"iss\":\"local-policy-gateway\",\"sub\":\"u\","
                        + "\"role\":\"reader\",\"iat\":" + at + ",\"nbf\":" + at
                        + ",\"exp\":" + (at + 1000) + "}").getBytes());
        return header + "." + payload + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
    }
}
