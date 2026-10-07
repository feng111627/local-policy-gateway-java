package com.github.feng111627.localpolicygatewayjava.tests;

import com.github.feng111627.localpolicygatewayjava.model.DenyReason;
import com.github.feng111627.localpolicygatewayjava.model.KeyState;
import com.github.feng111627.localpolicygatewayjava.model.StoredKey;
import com.github.feng111627.localpolicygatewayjava.model.TokenClaims;
import com.github.feng111627.localpolicygatewayjava.token.KeyStore;
import com.github.feng111627.localpolicygatewayjava.token.KeyStoreIntegrityException;
import com.github.feng111627.localpolicygatewayjava.token.LocalTokenService;
import com.github.feng111627.localpolicygatewayjava.token.TokenVerificationException;

import java.lang.reflect.Field;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 主线二：本地签名密钥的校验、轮换过渡期、吊销与防篡改，
 * 以及过期、签名不符、未知密钥等可区分拒绝原因。
 */
@DisplayName("主线二：本地密钥轮换与令牌校验")
class KeyRotationTokenTest {

    private KeyStore keyStore;
    private MutableClock clock;
    private LocalTokenService tokens;

    static final class MutableClock extends Clock {
        private Instant now = Instant.parse("2026-10-08T00:00:00Z");

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        keyStore = new KeyStore(clock);
        tokens = new LocalTokenService(keyStore, clock);
    }

    private TokenVerificationException expectDenied(DenyReason reason, String token) {
        TokenVerificationException ex = assertThrows(TokenVerificationException.class,
                () -> tokens.verify(token));
        assertEquals(reason, ex.getReason());
        return ex;
    }

    @Nested
    @DisplayName("轮换过渡用例")
    class RotationCases {

        @Test
        @DisplayName("用例2.1 新签发令牌通过校验，载荷角色可读")
        void freshTokenPasses() {
            String token = tokens.issue("alice", List.of("admin"), Duration.ofMinutes(10));
            TokenClaims claims = tokens.verify(token);
            assertEquals("alice", claims.sub());
            assertEquals(List.of("admin"), claims.roles());
        }

        @Test
        @DisplayName("用例2.2 轮换后：新密钥签发可用；旧密钥令牌在过渡期（PREVIOUS）仍可校验")
        void previousKeyTokenStillValidDuringTransition() {
            String oldToken = tokens.issue("bob", List.of("viewer"), Duration.ofHours(1));
            StoredKey oldKey = keyStore.activeKey();

            var rotation = keyStore.rotate();
            assertTrue(rotation.success());
            assertEquals(oldKey.kid(), rotation.previousKid());
            assertEquals(KeyState.PREVIOUS, keyStore.stateOf(oldKey.kid()));

            // 旧令牌仍可验
            assertEquals("bob", tokens.verify(oldToken).sub());
            // 新令牌用新 kid
            String newToken = tokens.issue("carol", List.of("viewer"), Duration.ofHours(1));
            assertNotNull(tokens.verify(newToken));
            assertTrue(!tokens.activeKid().equals(oldKey.kid()));
        }

        @Test
        @DisplayName("用例2.3 二次轮换后第一代密钥变为 REVOKED，其令牌被拒绝（KEY_REVOKED）")
        void keyRevokedAfterSecondRotation() {
            String firstToken = tokens.issue("bob", List.of("viewer"), Duration.ofHours(2));
            StoredKey firstKey = keyStore.activeKey();
            keyStore.rotate();
            keyStore.rotate();

            assertEquals(KeyState.REVOKED, keyStore.stateOf(firstKey.kid()));
            expectDenied(DenyReason.KEY_REVOKED, firstToken);
        }

        @Test
        @DisplayName("用例2.4 手动吊销当前密钥后，该密钥签发的令牌立即失效")
        void manualRevocationRejectsToken() {
            String token = tokens.issue("dave", List.of("viewer"), Duration.ofHours(1));
            StoredKey active = keyStore.activeKey();
            keyStore.revoke(active.kid());
            expectDenied(DenyReason.KEY_REVOKED, token);
        }
    }

    @Nested
    @DisplayName("拒绝原因区分用例")
    class RejectionCases {

        @Test
        @DisplayName("用例2.5 过期令牌 → TOKEN_EXPIRED")
        void expiredToken() {
            String token = tokens.issue("alice", List.of(), Duration.ofMinutes(1));
            clock.advance(Duration.ofMinutes(2));
            expectDenied(DenyReason.TOKEN_EXPIRED, token);
        }

        @Test
        @DisplayName("用例2.6 令牌签名被篡改（翻转签名字节）→ SIGNATURE_MISMATCH")
        void tamperedSignature() {
            String token = tokens.issue("alice", List.of(), Duration.ofMinutes(10));
            // 翻转“签名段”的首字符（尾部字符可能落在 Base64 无影响位，首字符一定改变签名字节）
            int dot = token.lastIndexOf('.');
            char first = token.charAt(dot + 1);
            String swapped = first == 'A' ? "B" : "A";
            String tampered = token.substring(0, dot + 1) + swapped + token.substring(dot + 2);
            expectDenied(DenyReason.SIGNATURE_MISMATCH, tampered);
        }

        @Test
        @DisplayName("用例2.7 载荷被篡改 → SIGNATURE_MISMATCH（签名不再匹配）")
        void tamperedPayload() {
            String token = tokens.issue("alice", List.of("viewer"), Duration.ofMinutes(10));
            String[] parts = token.split("\\.");
            String tampered = parts[0] + "." + parts[1] + "x." + parts[2];
            expectDenied(DenyReason.SIGNATURE_MISMATCH, tampered);
        }

        @Test
        @DisplayName("用例2.8 kid 指向不存在的密钥（密钥被从库中移除）→ UNKNOWN_KEY")
        @SuppressWarnings("unchecked")
        void unknownKey() throws Exception {
            String token = tokens.issue("alice", List.of(), Duration.ofMinutes(10));
            StoredKey active = keyStore.activeKey();
            Field field = KeyStore.class.getDeclaredField("keys");
            field.setAccessible(true);
            ((Map<String, StoredKey>) field.get(keyStore)).remove(active.kid());
            expectDenied(DenyReason.UNKNOWN_KEY, token);
        }

        @Test
        @DisplayName("用例2.9 结构非法令牌 → MALFORMED_TOKEN")
        void malformedToken() {
            expectDenied(DenyReason.MALFORMED_TOKEN, "not-a-token");
            expectDenied(DenyReason.MALFORMED_TOKEN, "a.b");
        }

        @Test
        @DisplayName("用例2.10 密钥材料被外部篡改（保留旧指纹）→ KEY_TAMPERED，令牌绝不放行")
        @SuppressWarnings("unchecked")
        void tamperedKeyMaterialIsRejected() throws Exception {
            String token = tokens.issue("alice", List.of("admin"), Duration.ofMinutes(10));
            StoredKey active = keyStore.activeKey();

            // 直接构造一把指纹不匹配的密钥：verifyIntegrity 必须拦截
            StoredKey forged = new StoredKey(active.kid(),
                    Base64.getEncoder().encodeToString(new byte[32]),
                    KeyState.ACTIVE, active.issuedAt(), active.fingerprint());
            assertThrows(KeyStoreIntegrityException.class, () -> keyStore.verifyIntegrity(forged));

            // 模拟攻击者直接改了密钥库文件：材料被替换，但旧指纹还在
            Field field = KeyStore.class.getDeclaredField("keys");
            field.setAccessible(true);
            ((Map<String, StoredKey>) field.get(keyStore)).put(active.kid(), forged);
            expectDenied(DenyReason.KEY_TAMPERED, token);
        }
    }
}
