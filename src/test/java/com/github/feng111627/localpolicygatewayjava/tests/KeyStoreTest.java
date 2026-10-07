package com.github.feng111627.localpolicygatewayjava.tests;

import com.github.feng111627.localpolicygatewayjava.auth.KeyState;
import com.github.feng111627.localpolicygatewayjava.auth.KeyStore;
import com.github.feng111627.localpolicygatewayjava.auth.TokenVerificationException;
import com.github.feng111627.localpolicygatewayjava.auth.VerificationFailure;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 本地密钥库：引导、轮换过渡、吊销、篡改检测。 */
class KeyStoreTest {

    @TempDir
    Path dir;

    private Path ksFile() {
        return dir.resolve("keystore.json");
    }

    @Test
    @DisplayName("文件不存在时引导生成唯一 ACTIVE 密钥并持久化")
    void bootstrapGeneratesActiveKey() {
        KeyStore ks = new KeyStore(ksFile());
        ks.load();
        assertEquals(1, ks.all().size());
        assertEquals(KeyState.ACTIVE, ks.activeKey().state());
        assertTrue(Files.exists(ksFile()));
    }

    @Test
    @DisplayName("轮换后新密钥 ACTIVE，旧密钥 RETIRED 且过渡期内仍可用")
    void rotateKeepsOldKeyUsableWithinOverlap() {
        long t0 = 1_000_000L;
        KeyStore ks = new KeyStore(ksFile());
        ks.load();
        String oldKid = ks.activeKey().kid();

        ks.rotate("k-new", t0, 60_000L);
        assertEquals("k-new", ks.activeKey().kid());
        assertEquals(KeyState.RETIRED, ks.find(oldKid).state());
        assertTrue(ks.isUsable(ks.find(oldKid), t0 + 1_000L));
        assertTrue(ks.isUsable(ks.find(oldKid), t0 + 60_000L));
    }

    @Test
    @DisplayName("过渡期结束后旧密钥不可用")
    void oldKeyUnusableAfterOverlap() {
        long t0 = 1_000_000L;
        KeyStore ks = new KeyStore(ksFile());
        ks.load();
        String oldKid = ks.activeKey().kid();
        ks.rotate("k-new", t0, 60_000L);
        assertFalse(ks.isUsable(ks.find(oldKid), t0 + 60_001L));
    }

    @Test
    @DisplayName("吊销的密钥永不可用")
    void revokedKeyNeverUsable() {
        KeyStore ks = new KeyStore(ksFile());
        ks.load();
        String kid = ks.activeKey().kid();
        ks.revoke(kid);
        assertEquals(KeyState.REVOKED, ks.find(kid).state());
        assertFalse(ks.isUsable(ks.find(kid), System.currentTimeMillis()));
    }

    @Test
    @DisplayName("篡改密钥库文件(改 state) -> KEYSTORE_TAMPERED")
    void tamperedStateDetected() throws Exception {
        KeyStore ks = new KeyStore(ksFile());
        ks.load();
        Path f = ksFile();
        String content = Files.readString(f, StandardCharsets.UTF_8);
        String tampered = content.replace("\"RETIRED", "XXX")
                .replace("\"ACTIVE\"", "\"RETIRED\"");
        Files.writeString(f, tampered, StandardCharsets.UTF_8);

        KeyStore reloaded = new KeyStore(f);
        TokenVerificationException e = assertThrows(TokenVerificationException.class,
                reloaded::load);
        assertEquals(VerificationFailure.KEYSTORE_TAMPERED, e.reason());
    }

    @Test
    @DisplayName("篡改 checksum 字段本身 -> KEYSTORE_TAMPERED")
    void tamperedChecksumDetected() throws Exception {
        KeyStore ks = new KeyStore(ksFile());
        ks.load();
        Path f = ksFile();
        String content = Files.readString(f, StandardCharsets.UTF_8);
        String tampered = content.replaceAll("\"checksum\" : \"[^\"]+\"",
                "\"checksum\" : \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"");
        Files.writeString(f, tampered, StandardCharsets.UTF_8);

        TokenVerificationException e = assertThrows(TokenVerificationException.class,
                () -> new KeyStore(f).load());
        assertEquals(VerificationFailure.KEYSTORE_TAMPERED, e.reason());
    }

    @Test
    @DisplayName("落盘后重新加载，状态一致")
    void reloadPersistedState() {
        KeyStore ks = new KeyStore(ksFile());
        ks.load();
        ks.rotate("k-2", System.currentTimeMillis(), 60_000L);
        KeyStore ks2 = new KeyStore(ksFile());
        ks2.load();
        assertEquals(2, ks2.all().size());
        assertEquals("k-2", ks2.activeKey().kid());
    }
}
