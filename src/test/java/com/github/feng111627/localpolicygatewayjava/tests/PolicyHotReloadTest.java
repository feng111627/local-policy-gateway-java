package com.github.feng111627.localpolicygatewayjava.tests;

import com.github.feng111627.localpolicygatewayjava.policy.AccessRequest;
import com.github.feng111627.localpolicygatewayjava.policy.Decision;
import com.github.feng111627.localpolicygatewayjava.policy.DenyReason;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyAdminService;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyEngine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 策略热更新：整体生效 / 失败保留旧版 / 并发下看不到半成品。 */
class PolicyHotReloadTest {

    private PolicyEngine engine;
    private PolicyAdminService admin;

    private static final AccessRequest READER_DOCS =
            new AccessRequest("reader", "docs", "read", Map.of());

    @BeforeEach
    void setUp() {
        engine = new PolicyEngine();
        admin = new PolicyAdminService(engine);
    }

    @Test
    @DisplayName("合法新版整体生效")
    void validUpdateAppliesAtomically() {
        admin.apply("""
                {"version":"v1","rules":[
                  {"id":"p1","effect":"PERMIT","role":"reader","resource":"docs","action":"read"}
                ]}""");
        assertTrue(engine.evaluate(READER_DOCS).permitted());

        var r = admin.apply("""
                {"version":"v2","rules":[
                  {"id":"d1","effect":"DENY","role":"reader","resource":"docs","action":"read"}
                ]}""");
        assertTrue(r.applied());
        assertEquals("v2", engine.current().version());
        Decision d = engine.evaluate(READER_DOCS);
        assertFalse(d.permitted());
        assertEquals("d1", d.matchedRuleId());
    }

    @Test
    @DisplayName("语法错误的新版整体不生效，旧版完整保留")
    void badSyntaxKeepsPrevious() {
        admin.apply("""
                {"version":"v1","rules":[
                  {"id":"p1","effect":"PERMIT","role":"reader","resource":"docs","action":"read"}
                ]}""");
        var r = admin.apply("{ broken json");
        assertFalse(r.applied());
        assertEquals("SYNTAX_ERROR", r.reason());
        assertEquals("v1", engine.current().version());
        assertTrue(engine.evaluate(READER_DOCS).permitted());
    }

    @Test
    @DisplayName("缺字段的新版不生效，原因 MISSING_FIELD，旧版保留")
    void missingFieldKeepsPrevious() {
        admin.apply("""
                {"version":"v1","rules":[
                  {"id":"p1","effect":"PERMIT","role":"reader","resource":"docs","action":"read"}
                ]}""");
        var r = admin.apply("""
                {"version":"v2","rules":[
                  {"id":"p2","role":"reader","resource":"docs","action":"read"}
                ]}""");
        assertFalse(r.applied());
        assertEquals("MISSING_FIELD", r.reason());
        assertEquals("v1", engine.current().version());
    }

    @Test
    @DisplayName("矛盾规则的新版不生效，原因 CONTRADICTION，旧版保留")
    void contradictionKeepsPrevious() {
        admin.apply("""
                {"version":"v1","rules":[
                  {"id":"p1","effect":"PERMIT","role":"reader","resource":"docs","action":"read"}
                ]}""");
        var r = admin.apply("""
                {"version":"v2","rules":[
                  {"id":"a","effect":"PERMIT","priority":1,
                   "role":"reader","resource":"docs","action":"read"},
                  {"id":"b","effect":"DENY","priority":1,
                   "role":"reader","resource":"docs","action":"read"}
                ]}""");
        assertFalse(r.applied());
        assertEquals("CONTRADICTION", r.reason());
        assertTrue(engine.evaluate(READER_DOCS).permitted());
    }

    @Test
    @DisplayName("并发判定期间热更新：所有判定结果要么来自旧版要么来自新版，无半成品")
    void concurrentReadersSeeWholeVersionsOnly() throws Exception {
        admin.apply("""
                {"version":"v1","rules":[
                  {"id":"p1","effect":"PERMIT","role":"reader","resource":"docs","action":"read"}
                ]}""");

        int threads = 8;
        int iterations = 500;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger permits = new AtomicInteger();
        AtomicInteger denies = new AtomicInteger();
        AtomicInteger other = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            Thread t = new Thread(() -> {
                try {
                    start.await();
                    for (int j = 0; j < iterations; j++) {
                        Decision d = engine.evaluate(READER_DOCS);
                        if (d.permitted()) {
                            assertEquals("v1", d.policyVersion());
                            assertEquals("p1", d.matchedRuleId());
                            permits.incrementAndGet();
                        } else if (d.denyReason() == DenyReason.EXPLICIT_DENY) {
                            assertEquals("v2", d.policyVersion());
                            assertEquals("d1", d.matchedRuleId());
                            denies.incrementAndGet();
                        } else {
                            other.incrementAndGet();
                        }
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
            t.start();
        }

        start.countDown();
        admin.apply("""
                {"version":"v2","rules":[
                  {"id":"d1","effect":"DENY","role":"reader","resource":"docs","action":"read"}
                ]}""");
        done.await();

        assertEquals(0, other.get(), "不允许出现既非旧版也非新版的中间态结果");
        assertEquals(threads * iterations, permits.get() + denies.get());
    }
}
