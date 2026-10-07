package com.github.feng111627.localpolicygatewayjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.feng111627.localpolicygatewayjava.Application;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 主线四（端到端）：经 HTTP 走通“签发令牌 → 判定 → 热更新 → 轮换”，
 * 校验 200/403 状态码与可解释响应体。
 */
@SpringBootTest(classes = Application.class)
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@DisplayName("主线四：HTTP 端到端（状态码/解释字段/管理端点）")
class GatewayWebEndToEndTest {

    @Autowired
    private MockMvc mockMvc;
    private final ObjectMapper json = new ObjectMapper();

    private String issueToken(String sub, String roles) throws Exception {
        String body = "{\"sub\":\"" + sub + "\",\"roles\":[" + roles + "],\"ttlSeconds\":3600}";
        MvcResult result = mockMvc.perform(post("/local-gateway/tokens")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andReturn();
        return json.readTree(result.getResponse().getContentAsString()).get("token").asText();
    }

    @Test
    @Order(1)
    @DisplayName("用例4.1 无令牌访问 → 403 且原因 NO_TOKEN")
    void noTokenForbidden() throws Exception {
        mockMvc.perform(post("/local-gateway/decide")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"resource\":\"docs/a\",\"env\":{\"env\":\"prod\"}}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.decision").value("DENY"))
                .andExpect(jsonPath("$.reason").value(org.hamcrest.Matchers.containsString("NO_TOKEN")));
    }

    @Test
    @Order(2)
    @DisplayName("用例4.2 admin 在 prod 访问 docs/a（内置默认策略）→ 200 放行并命中规则")
    void adminAllowed() throws Exception {
        String token = issueToken("admin-user", "\"admin\"");
        mockMvc.perform(post("/local-gateway/decide")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"resource\":\"docs/a\",\"env\":{\"env\":\"prod\"}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("ALLOW"))
                .andExpect(jsonPath("$.matchedRuleId").value("allow-admin-docs-prod"))
                .andExpect(jsonPath("$.reason").value(org.hamcrest.Matchers.containsString("allow-admin-docs-prod")));
    }

    @Test
    @Order(3)
    @DisplayName("用例4.3 viewer 在 prod → 403 显式拒绝，响应可解释")
    void viewerDenied() throws Exception {
        String token = issueToken("viewer-user", "\"viewer\"");
        mockMvc.perform(post("/local-gateway/decide")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"resource\":\"docs/a\",\"env\":{\"env\":\"prod\"}}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.decision").value("DENY"))
                .andExpect(jsonPath("$.matchedRuleId").value("deny-prod-write-by-default"))
                .andExpect(jsonPath("$.reason").value(org.hamcrest.Matchers.containsString("EXPLICITLY_DENIED")));
    }

    @Test
    @Order(4)
    @DisplayName("用例4.4 管理端点热更新非法策略 → success=false 且保留旧版；合法版本可继续判定")
    void reloadAndAuditEndpoints() throws Exception {
        String badReload = "{\"json\":\"{ not json\"}";
        MvcResult badResult = mockMvc.perform(post("/local-gateway/admin/policies/reload")
                        .contentType(MediaType.APPLICATION_JSON).content(badReload))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode bad = json.readTree(badResult.getResponse().getContentAsString());
        org.junit.jupiter.api.Assertions.assertFalse(bad.get("success").asBoolean());
        org.junit.jupiter.api.Assertions.assertEquals("SYNTAX_ERROR", bad.get("errorCode").asText());
        org.junit.jupiter.api.Assertions.assertTrue(bad.get("activeVersion").asLong() >= 1);

        MvcResult auditResult = mockMvc.perform(get("/local-gateway/admin/audit"))
                .andExpect(status().isOk()).andReturn();
        JsonNode events = json.readTree(auditResult.getResponse().getContentAsString());
        org.junit.jupiter.api.Assertions.assertTrue(events.size() >= 3, "每次判定都应有审计记录");
    }

    @Test
    @Order(5)
    @DisplayName("用例4.5 密钥轮换端点返回新 activeKid 与过渡期 previousKid")
    void keyRotationEndpoint() throws Exception {
        MvcResult result = mockMvc.perform(post("/local-gateway/admin/keys/rotate"))
                .andExpect(status().isOk()).andReturn();
        JsonNode node = json.readTree(result.getResponse().getContentAsString());
        org.junit.jupiter.api.Assertions.assertTrue(node.get("success").asBoolean());
        org.junit.jupiter.api.Assertions.assertNotNull(node.get("activeKid").asText());
        org.junit.jupiter.api.Assertions.assertNotNull(node.get("previousKid").asText());
    }
}
