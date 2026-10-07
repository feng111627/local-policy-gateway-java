package com.github.feng111627.localpolicygatewayjava.tests;

import com.github.feng111627.localpolicygatewayjava.policy.PolicyLoadException;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyLoadFailure;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 策略加载失败必须可区分、不可静默跳过。 */
class PolicyParserTest {

    private final PolicyParser parser = new PolicyParser();

    @Test
    @DisplayName("JSON 语法错误 -> SYNTAX_ERROR")
    void syntaxError() {
        PolicyLoadException e = assertThrows(PolicyLoadException.class,
                () -> parser.parse("{not-json"));
        assertEquals(PolicyLoadFailure.SYNTAX_ERROR, e.reason());
    }

    @Test
    @DisplayName("缺少 rules -> MISSING_FIELD")
    void missingRules() {
        PolicyLoadException e = assertThrows(PolicyLoadException.class,
                () -> parser.parse("{\"version\":\"v1\"}"));
        assertEquals(PolicyLoadFailure.MISSING_FIELD, e.reason());
    }

    @Test
    @DisplayName("规则缺少必填字段 effect -> MISSING_FIELD")
    void missingEffectField() {
        PolicyLoadException e = assertThrows(PolicyLoadException.class,
                () -> parser.parse("""
                        {"rules":[{"id":"r1","role":"r","resource":"x"}]}"""));
        assertEquals(PolicyLoadFailure.MISSING_FIELD, e.reason());
        assertTrue(e.getMessage().contains("effect"));
    }

    @Test
    @DisplayName("effect 取值非法 -> INVALID_VALUE")
    void invalidEffect() {
        PolicyLoadException e = assertThrows(PolicyLoadException.class,
                () -> parser.parse("""
                        {"rules":[{"id":"r1","effect":"MAYBE",
                        "role":"r","resource":"x"}]}"""));
        assertEquals(PolicyLoadFailure.INVALID_VALUE, e.reason());
    }

    @Test
    @DisplayName("priority 非整数 -> INVALID_VALUE")
    void invalidPriority() {
        PolicyLoadException e = assertThrows(PolicyLoadException.class,
                () -> parser.parse("""
                        {"rules":[{"id":"r1","effect":"PERMIT","priority":"high",
                        "role":"r","resource":"x"}]}"""));
        assertEquals(PolicyLoadFailure.INVALID_VALUE, e.reason());
    }

    @Test
    @DisplayName("规则 ID 重复 -> DUPLICATE_RULE_ID")
    void duplicateId() {
        PolicyLoadException e = assertThrows(PolicyLoadException.class,
                () -> parser.parse("""
                        {"rules":[
                          {"id":"r1","effect":"PERMIT","role":"a","resource":"x"},
                          {"id":"r1","effect":"DENY","role":"b","resource":"y"}
                        ]}"""));
        assertEquals(PolicyLoadFailure.DUPLICATE_RULE_ID, e.reason());
    }

    @Test
    @DisplayName("同范围同优先级效果相反 -> CONTRADICTION")
    void contradiction() {
        PolicyLoadException e = assertThrows(PolicyLoadException.class,
                () -> parser.parse("""
                        {"rules":[
                          {"id":"p","effect":"PERMIT","priority":5,
                           "role":"r","resource":"x","action":"read"},
                          {"id":"d","effect":"DENY","priority":5,
                           "role":"r","resource":"x","action":"read"}
                        ]}"""));
        assertEquals(PolicyLoadFailure.CONTRADICTION, e.reason());
        assertTrue(e.getMessage().contains("p") && e.getMessage().contains("d"));
    }

    @Test
    @DisplayName("效果相反但优先级不同不算矛盾，可以加载")
    void differentPriorityNotContradiction() {
        var policy = parser.parse("""
                {"rules":[
                  {"id":"p","effect":"PERMIT","priority":6,
                   "role":"r","resource":"x","action":"read"},
                  {"id":"d","effect":"DENY","priority":5,
                   "role":"r","resource":"x","action":"read"}
                ]}""");
        assertEquals(2, policy.rules().size());
    }
}
