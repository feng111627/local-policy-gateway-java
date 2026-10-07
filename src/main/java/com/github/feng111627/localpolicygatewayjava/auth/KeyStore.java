package com.github.feng111627.localpolicygatewayjava.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * 本地密钥库。
 *
 * <p>文件为 JSON：{@code {version, checksum, keys[]}}。checksum =
 * SHA-256(keys 数组的规范化 JSON)，任何对密钥条目的手工篡改（改 secret、改 state、加条目）
 * 都会使校验和不匹配，加载时以 {@link VerificationFailure#KEYSTORE_TAMPERED} 拒绝，
 * 被篡改的密钥永远不会进入验签流程。
 *
 * <p>轮换语义：{@link #rotate(String)} 把当前 ACTIVE 密钥置为 RETIRED 并写入过渡期截止时刻，
 * 新密钥成为 ACTIVE；过渡期内旧密钥仍可验签，过期或被吊销的密钥不行。
 */
public class KeyStore {

    private static final int SECRET_BYTES = 32;
    private final SecureRandom random = new SecureRandom();
    private final ObjectMapper mapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    private final Path file;
    private volatile List<SigningKey> keys = List.of();

    public KeyStore(Path file) {
        this.file = file;
    }

    /**
     * 加载密钥库：文件不存在时引导生成首把 ACTIVE 密钥；
     * 文件存在但校验和不符时拒绝加载（绝不忽略篡改）。
     */
    public synchronized void load() {
        if (!Files.exists(file)) {
            String kid = "k-" + Long.toHexString(System.currentTimeMillis());
            SigningKey initial = new SigningKey(kid, KeyAlgorithm.HMAC_SHA256, newSecret(),
                    KeyState.ACTIVE, System.currentTimeMillis(), 0L);
            keys = List.of(initial);
            save();
            return;
        }
        try {
            JsonNode root = mapper.readTree(Files.readString(file, StandardCharsets.UTF_8));
            JsonNode keysNode = root.get("keys");
            String storedChecksum = root.path("checksum").asText(null);
            if (keysNode == null || storedChecksum == null) {
                throw new TokenVerificationException(VerificationFailure.KEYSTORE_TAMPERED,
                        "密钥库缺少 keys/checksum 字段，疑似被篡改或截断: " + file);
            }
            String actual = checksum(mapper.writeValueAsString(keysNode));
            if (!MessageDigest.isEqual(
                    actual.getBytes(StandardCharsets.UTF_8),
                    storedChecksum.getBytes(StandardCharsets.UTF_8))) {
                throw new TokenVerificationException(VerificationFailure.KEYSTORE_TAMPERED,
                        "密钥库校验和不匹配，文件已被篡改: " + file);
            }
            List<SigningKey> loaded = new ArrayList<>();
            for (JsonNode k : keysNode) {
                loaded.add(new SigningKey(
                        k.get("kid").asText(),
                        KeyAlgorithm.valueOf(k.get("algorithm").asText()),
                        Base64.getDecoder().decode(k.get("secret").asText()),
                        KeyState.valueOf(k.get("state").asText()),
                        k.get("createdAt").asLong(),
                        k.path("retireAt").asLong(0L)));
            }
            long activeCount = loaded.stream().filter(k -> k.state() == KeyState.ACTIVE).count();
            if (activeCount != 1) {
                throw new TokenVerificationException(VerificationFailure.KEYSTORE_TAMPERED,
                        "密钥库必须恰好包含 1 把 ACTIVE 密钥，实际 " + activeCount + " 把");
            }
            keys = List.copyOf(loaded);
        } catch (TokenVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new TokenVerificationException(VerificationFailure.KEYSTORE_TAMPERED,
                    "密钥库无法解析: " + e.getMessage());
        }
    }

    /** 原子写盘（先临时文件再 move），避免写出半个文件。 */
    public synchronized void save() {
        try {
            List<JsonNode> keyNodes = new ArrayList<>();
            for (SigningKey k : keys) {
                var n = mapper.createObjectNode();
                n.put("kid", k.kid());
                n.put("algorithm", k.algorithm().name());
                n.put("secret", Base64.getEncoder().encodeToString(k.secret()));
                n.put("state", k.state().name());
                n.put("createdAt", k.createdAtEpochMillis());
                n.put("retireAt", k.retireAtEpochMillis());
                keyNodes.add(n);
            }
            var keysArray = mapper.createArrayNode();
            keyNodes.forEach(keysArray::add);
            String canonical = mapper.writeValueAsString(keysArray);

            var root = mapper.createObjectNode();
            root.put("version", 1);
            root.put("checksum", checksum(canonical));
            root.set("keys", keysArray);

            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            java.nio.file.Files.createDirectories(file.toAbsolutePath().getParent());
            Files.writeString(tmp, mapper.writeValueAsString(root), StandardCharsets.UTF_8);
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception e) {
            throw new IllegalStateException("密钥库写盘失败: " + e.getMessage(), e);
        }
    }

    public SigningKey activeKey() {
        return keys.stream().filter(k -> k.state() == KeyState.ACTIVE).findFirst()
                .orElseThrow(() -> new IllegalStateException("密钥库没有 ACTIVE 密钥"));
    }

    public SigningKey find(String kid) {
        return keys.stream().filter(k -> k.kid().equals(kid)).findFirst().orElse(null);
    }

    public List<SigningKey> all() {
        return keys;
    }

    /**
     * 轮换：旧 ACTIVE -> RETIRED（过渡期截止 = now + overlapMillis），新密钥 -> ACTIVE。
     * 过渡期内旧密钥仍可验签；超过渡期等同于不可用密钥。
     */
    public synchronized SigningKey rotate(String newKid) {
        return rotate(newKid, System.currentTimeMillis());
    }

    /** 可注入“当前时间”的重载，便于确定性测试。 */
    public synchronized SigningKey rotate(String newKid, long nowMillis) {
        return rotate(newKid, nowMillis, 0L);
    }

    /** 可注入当前时间与过渡期长度的重载。 */
    public synchronized SigningKey rotate(String newKid, long nowMillis, long overlapMillis) {
        if (find(newKid) != null) {
            throw new IllegalArgumentException("新密钥 ID 已存在: " + newKid);
        }
        List<SigningKey> next = new ArrayList<>();
        SigningKey fresh = new SigningKey(newKid, KeyAlgorithm.HMAC_SHA256, newSecret(),
                KeyState.ACTIVE, nowMillis, 0L);
        for (SigningKey k : keys) {
            if (k.state() == KeyState.ACTIVE) {
                next.add(new SigningKey(k.kid(), k.algorithm(), k.secret(), KeyState.RETIRED,
                        k.createdAtEpochMillis(), nowMillis + overlapMillis));
            } else {
                next.add(k);
            }
        }
        next.add(fresh);
        keys = List.copyOf(next);
        save();
        return fresh;
    }

    public synchronized void revoke(String kid) {
        List<SigningKey> next = new ArrayList<>();
        boolean found = false;
        for (SigningKey k : keys) {
            if (k.kid().equals(kid)) {
                found = true;
                next.add(new SigningKey(k.kid(), k.algorithm(), k.secret(), KeyState.REVOKED,
                        k.createdAtEpochMillis(), k.retireAtEpochMillis()));
            } else {
                next.add(k);
            }
        }
        if (!found) {
            throw new IllegalArgumentException("未知密钥 ID: " + kid);
        }
        keys = List.copyOf(next);
        save();
    }

    /** 把指定密钥提升为 ACTIVE（其余 ACTIVE 转为 RETIRED）。 */
    public synchronized void promote(String kid) {
        SigningKey target = find(kid);
        if (target == null) {
            throw new IllegalArgumentException("未知密钥 ID: " + kid);
        }
        List<SigningKey> next = new ArrayList<>();
        for (SigningKey k : keys) {
            if (k.kid().equals(kid)) {
                next.add(new SigningKey(k.kid(), k.algorithm(), k.secret(), KeyState.ACTIVE,
                        k.createdAtEpochMillis(), 0L));
            } else if (k.state() == KeyState.ACTIVE) {
                next.add(new SigningKey(k.kid(), k.algorithm(), k.secret(), KeyState.RETIRED,
                        k.createdAtEpochMillis(), System.currentTimeMillis()));
            } else {
                next.add(k);
            }
        }
        keys = List.copyOf(next);
        save();
    }

    /** 该密钥当前是否可用于验签（ACTIVE 始终可用；RETIRED 仅过渡期内可用；REVOKED 永不可用）。 */
    public boolean isUsable(SigningKey k, long nowMillis) {
        return switch (k.state()) {
            case ACTIVE -> true;
            case RETIRED -> nowMillis <= k.retireAtEpochMillis();
            case REVOKED -> false;
        };
    }

    private byte[] newSecret() {
        byte[] b = new byte[SECRET_BYTES];
        random.nextBytes(b);
        return b;
    }

    private String checksum(String canonicalKeysJson) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(canonicalKeysJson.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(digest);
    }
}
