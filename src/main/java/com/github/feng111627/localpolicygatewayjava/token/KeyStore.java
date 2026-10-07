package com.github.feng111627.localpolicygatewayjava.token;

import com.github.feng111627.localpolicygatewayjava.model.KeyRotationResult;
import com.github.feng111627.localpolicygatewayjava.model.KeyState;
import com.github.feng111627.localpolicygatewayjava.model.StoredKey;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 本地签名密钥库。
 *
 * <p>语义：
 * <ul>
 *   <li>启动时本地随机生成第一把 ACTIVE 密钥，全程不接触外部服务；</li>
 *   <li>{@link #rotate()} 生成新 ACTIVE 密钥，旧 ACTIVE 降级为 PREVIOUS（轮换过渡期内仍可校验），
 *       更早的 PREVIOUS 被吊销（REVOKED）；</li>
 *   <li>每把密钥都带密钥材料完整性指纹（用进程内 pepper 计算的 HMAC），
 *       外部篡改密钥材料或状态但无法重算 pepper 指纹时，{@link #verifyIntegrity} 会拒绝它。</li>
 * </ul>
 */
@Component
public class KeyStore {

    /** 完整性指纹使用的本地 pepper：与密钥材料分开存放，篡改密钥文件的人拿不到它。 */
    static final byte[] FINGERPRINT_PEPPER =
            "local-policy-gateway/integrity-pepper/v1".getBytes(StandardCharsets.UTF_8);

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int KEY_BYTES = 32;

    private final Clock clock;
    private final Map<String, StoredKey> keys = new ConcurrentHashMap<>();
    private final AtomicReference<String> activeKid = new AtomicReference<>();

    public KeyStore() {
        this(Clock.systemUTC());
    }

    public KeyStore(Clock clock) {
        this.clock = clock;
        StoredKey first = generateKey(1);
        keys.put(first.kid(), first);
        activeKid.set(first.kid());
    }

    private StoredKey generateKey(int serial) {
        byte[] raw = new byte[KEY_BYTES];
        RANDOM.nextBytes(raw);
        String kid = "key-" + clock.instant().getEpochSecond() + "-" + serial + "-"
                + Integer.toHexString(RANDOM.nextInt());
        String secret = Base64.getEncoder().encodeToString(raw);
        long issuedAt = clock.instant().getEpochSecond();
        StoredKey key = new StoredKey(kid, secret, KeyState.ACTIVE, issuedAt, null);
        return withFingerprint(key);
    }

    private static StoredKey withFingerprint(StoredKey key) {
        return new StoredKey(key.kid(), key.secret(), key.state(), key.issuedAt(), fingerprint(key));
    }

    static String fingerprint(StoredKey key) {
        String material = key.kid() + "|" + key.secret() + "|" + key.state().name();
        return hmacHex(FINGERPRINT_PEPPER, material);
    }

    static String hmacHex(byte[] keyBytes, String message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(keyBytes, "HmacSHA256"));
            byte[] out = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return toHex(out);
        } catch (Exception e) {
            throw new IllegalStateException("无法计算 HMAC-SHA256", e);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    /** 校验密钥完整性指纹；不一致说明密钥材料或状态被篡改。 */
    public void verifyIntegrity(StoredKey key) {
        String expected = fingerprint(key);
        if (!MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                key.fingerprint() == null ? new byte[0] : key.fingerprint().getBytes(StandardCharsets.UTF_8))) {
            throw new KeyStoreIntegrityException("密钥 " + key.kid() + " 完整性指纹不匹配，密钥可能已被篡改");
        }
    }

    public StoredKey activeKey() {
        return keys.get(activeKid.get());
    }

    public Optional<StoredKey> find(String kid) {
        return Optional.ofNullable(kid).map(keys::get);
    }

    public StoredKey get(String kid) {
        StoredKey key = keys.get(kid);
        if (key == null) {
            throw new IllegalArgumentException("未知密钥: " + kid);
        }
        return key;
    }

    /**
     * 轮换密钥：新密钥成为 ACTIVE；旧 ACTIVE 变为 PREVIOUS（过渡可验）；已有 PREVIOUS 变为 REVOKED。
     */
    public synchronized KeyRotationResult rotate() {
        StoredKey oldActive = activeKey();
        String oldKid = oldActive == null ? null : oldActive.kid();

        List<StoredKey> snapshot = new ArrayList<>(keys.values());
        int serial = (int) snapshot.stream().filter(k -> k.state() != KeyState.REVOKED).count() + 1;
        StoredKey fresh = generateKey(serial);
        keys.put(fresh.kid(), fresh);

        String previousKid = null;
        for (StoredKey key : snapshot) {
            if (key.state() == KeyState.PREVIOUS) {
                keys.put(key.kid(), withFingerprint(
                        new StoredKey(key.kid(), key.secret(), KeyState.REVOKED, key.issuedAt(), null)));
            } else if (key.kid().equals(oldKid)) {
                StoredKey previous = withFingerprint(
                        new StoredKey(key.kid(), key.secret(), KeyState.PREVIOUS, key.issuedAt(), null));
                keys.put(key.kid(), previous);
                previousKid = previous.kid();
            }
        }
        activeKid.set(fresh.kid());
        return new KeyRotationResult(true, fresh.kid(), previousKid,
                "轮换成功：新当前密钥 " + fresh.kid() + "，过渡期旧密钥 " + previousKid);
    }

    public synchronized void revoke(String kid) {
        StoredKey key = get(kid);
        keys.put(kid, withFingerprint(
                new StoredKey(key.kid(), key.secret(), KeyState.REVOKED, key.issuedAt(), null)));
    }

    public List<StoredKey> all() {
        return List.copyOf(keys.values());
    }

    public KeyState stateOf(String kid) {
        StoredKey key = keys.get(kid);
        return key == null ? null : key.state();
    }
}
