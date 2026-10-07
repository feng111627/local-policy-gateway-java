package com.github.feng111627.localpolicygatewayjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.feng111627.localpolicygatewayjava.auth.KeyStore;
import com.github.feng111627.localpolicygatewayjava.auth.TokenService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * HTTP 端到端：经过真实的控制器 -> 网关编排 -> 审计链路，
 * 覆盖放行、拒绝、坏令牌、策略热更新、密钥轮换五条主线在 Web 层的表现。
 */
@SpringBootTest(properties = {
        "gateway.policy-file=target/test-policies/e2e-policy.json",
        "gateway.key-store-file=target/test-keystores/e2e-keystore.json"
})
@AutoConfigureMockMvc
class WebEndToEndTest {

    @Autowired
    private MockMvc mvc;
    @Autowired
    private TokenService tokens;
    @Autowired
    private KeyStore keyStore;

    static {
        // 上下文启动前准备初始策略文件，保证首个用例读到的是可放行的旧版
        try {
            java.nio.file.Path policyDir =
                    java.nio.file.Paths.get("target/test-policies");
            java.nio.file.Files.createDirectories(policyDir);
            java.nio.file.Files.createDirectories(
                    java.nio.file.Paths.get("target/test-keystores"));
            java.nio.file.Files.writeString(policyDir.resolve("e2e-policy.json"), """
                    {"version":"e2e-initial","rules":[
                      {"id":"reader-read-docs","effect":"PERMIT","priority":10,
                       "role":"reader","resource":"docs","action":"read"},
                      {"id":"reader-read-docs-prod-deny","effect":"DENY","priority":20,
                       "role":"reader","resource":"docs","action":"read","env":{"env":"prod"}}
                    ]}""", java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private final ObjectMapper mapper = new ObjectMapper();

    private String body(String token, String resource, String action, String envJson) {
        String env = envJson == null ? "{}" : envJson;
        return "{\"token\":\"" + token + "\",\"resource\":\"" + resource
                + "\",\"action\":\"" + action + "\",\"env\":" + env + "}";
    }

    private JsonNode callAccess(String jsonBody) throws Exception {
        String resp = mvc.perform(post("/access")
                        .contentType(MediaType.APPLICATION_JSON).content(jsonBody))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return mapper.readTree(resp);
    }

    @Test
    @DisplayName("Web: 合法令牌命中 PERMIT -> permitted=true")
    void permitViaHttp() throws Exception {
        String token = tokens.issue("alice", "reader", 60_000L);
        JsonNode resp = callAccess(body(token, "docs", "read", null));
        assertTrue(resp.get("permitted").asBoolean());
        assertEquals("PERMIT", resp.get("reasonCode").asText());
        assertEquals("reader-read-docs", resp.get("matchedRuleId").asText());
    }

    @Test
    @DisplayName("Web: 生产环境读文档命中环境 DENY -> permitted=false")
    void envDenyViaHttp() throws Exception {
        String token = tokens.issue("bob", "reader", 60_000L);
        JsonNode resp = callAccess(body(token, "docs", "read", "{\"env\":\"prod\"}"));
        assertFalse(resp.get("permitted").asBoolean());
        assertEquals("EXPLICIT_DENY", resp.get("reasonCode").asText());
    }

    @Test
    @DisplayName("Web: 篡改令牌 -> HTTP 200 判定为拒绝，reason=BAD_SIGNATURE")
    void badTokenViaHttp() throws Exception {
        String token = tokens.issue("bob", "reader", 60_000L);
        String[] parts = token.split("\\.");
        // 用同长度的错误签名整体替换，确定性触发 BAD_SIGNATURE
        parts[2] = "A".repeat(parts[2].length());
        String tampered = String.join(".", parts);

        JsonNode resp = callAccess(body(tampered, "docs", "read", null));
        assertFalse(resp.get("permitted").asBoolean());
        assertEquals("BAD_SIGNATURE", resp.get("reasonCode").asText());
    }

    @Test
    @DisplayName("Web: 缺失 token -> 401 且 reason=MALFORMED_TOKEN")
    void missingTokenViaHttp() throws Exception {
        String resp = mvc.perform(post("/access")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"resource\":\"docs\",\"action\":\"read\"}"))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        assertTrue(resp.contains("MALFORMED_TOKEN"));
    }

    @Test
    @DisplayName("Web: 管理端热更新非法策略 -> applied=false 且保留旧版，可区分原因")
    void invalidHotUpdateViaHttpKeepsOld() throws Exception {
        String token = tokens.issue("carol", "reader", 60_000L);
        assertTrue(callAccess(body(token, "docs", "read", null)).get("permitted").asBoolean());

        String updateResp = mvc.perform(post("/admin/policies")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"rules\":[{\"id\":\"x\"}]}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        JsonNode update = mapper.readTree(updateResp);
        assertFalse(update.get("applied").asBoolean());
        assertEquals("MISSING_FIELD", update.get("reason").asText());

        // 旧版策略仍然可用
        assertTrue(callAccess(body(token, "docs", "read", null)).get("permitted").asBoolean());
    }

    @Test
    @DisplayName("Web: 合法热更新整体生效，随后判定按新版拒绝")
    void validHotUpdateViaHttp() throws Exception {
        String token = tokens.issue("dave", "reader", 60_000L);
        String updateResp = mvc.perform(post("/admin/policies")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"version\":\"e2e-deny\",\"rules\":["
                                + "{\"id\":\"deny-all\",\"effect\":\"DENY\","
                                + "\"role\":\"*\",\"resource\":\"*\",\"action\":\"*\"}]}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        JsonNode update = mapper.readTree(updateResp);
        assertTrue(update.get("applied").asBoolean());

        JsonNode resp = callAccess(body(token, "docs", "read", null));
        assertFalse(resp.get("permitted").asBoolean());
        assertEquals("e2e-deny", resp.get("policyVersion").asText());
    }

    @Test
    @DisplayName("Web: 轮换后过渡期内旧令牌仍可访问")
    void oldTokenStillWorksAfterRotationViaHttp() throws Exception {
        String token = tokens.issue("erin", "reader", 60_000L);
        String rotateResp = mvc.perform(post("/admin/keys/rotate"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        JsonNode rotation = mapper.readTree(rotateResp);
        assertEquals("ROTATED", rotation.get("status").asText().split(":")[0]);

        JsonNode resp = callAccess(body(token, "docs", "read", null));
        assertTrue(resp.get("permitted").asBoolean());
    }
}
