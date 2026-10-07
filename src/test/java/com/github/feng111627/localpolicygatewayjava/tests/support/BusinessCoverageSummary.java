package com.github.feng111627.localpolicygatewayjava.tests.support;

import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 测试执行总结监听器：
 * 运行结束时按“业务主线”打印覆盖了哪些业务、每条主线的用例数与通过情况，
 * 输出形如 {@code [测试覆盖] 放行主线: 3/3 通过}，方便从日志核对覆盖面。
 */
public class BusinessCoverageSummary implements TestExecutionListener {

    private static final Map<String, String> CLASS_TO_BUSINESS = Map.ofEntries(
            Map.entry("PolicyEngineTest$Permit", "放行主线"),
            Map.entry("PolicyEngineTest$Deny", "拒绝主线(默认拒绝/显式拒绝/环境属性)"),
            Map.entry("PolicyEngineTest$Priority", "优先级与冲突处理"),
            Map.entry("PolicyParserTest", "策略加载失败可区分(缺字段/语法/矛盾)"),
            Map.entry("TokenServiceTest$Happy", "令牌正常校验"),
            Map.entry("TokenServiceTest$Failures", "令牌拒绝原因可区分(过期/吊销/签名/未知密钥)"),
            Map.entry("TokenServiceTest$Rotation", "密钥轮换过渡语义"),
            Map.entry("KeyStoreTest", "本地密钥库(引导/轮换/吊销/防篡改)"),
            Map.entry("PolicyHotReloadTest", "策略热更新(整体生效/失败保留/并发一致)"),
            Map.entry("GatewayServiceTest", "端到端编排与审计留痕"),
            Map.entry("WebEndToEndTest", "HTTP 端到端(放行/拒绝/坏令牌/热更新/轮换)"),
            Map.entry("ApplicationTests", "Spring 上下文启动"));

    private final Map<String, int[]> stats = new LinkedHashMap<>();

    @Override
    public void testPlanExecutionStarted(TestPlan testPlan) {
        CLASS_TO_BUSINESS.values().forEach(v -> stats.put(v, new int[]{0, 0}));
    }

    @Override
    public void executionFinished(TestIdentifier id, TestExecutionResult result) {
        if (!id.isTest()) {
            return;
        }
        if (Boolean.getBoolean("coverage.debug")) {
            System.out.println("[coverage-debug] " + id.getUniqueId());
        }
        String business = resolveBusiness(id);
        int[] s = stats.computeIfAbsent(business, k -> new int[]{0, 0});
        s[0]++;
        if (result.getStatus() == TestExecutionResult.Status.SUCCESSFUL) {
            s[1]++;
        }
    }

    /**
     * 用 TestPlan 的父子关系向上找最近的类容器：
     * 普通用例直接命中 [class:...]；@Nested 用例先经过 [nested-class:Outer$Inner]。
     * 解析时对各段做统一的 {@code 段类型:值} 提取，不依赖固定位置。
     */
    private String resolveBusiness(TestIdentifier id) {
        String uid = id.getUniqueId();
        String classValue = segmentValue(uid, "class");
        String nestedValue = segmentValue(uid, "nested-class");
        if (nestedValue != null && classValue != null) {
            // nested-class 段只给内部类短名，拼上外层类短名得到 Outer$Inner
            String key = shortName(classValue) + "$" + nestedValue;
            return CLASS_TO_BUSINESS.getOrDefault(key, "其他");
        }
        if (classValue != null) {
            return CLASS_TO_BUSINESS.getOrDefault(shortName(classValue), "其他");
        }
        return "其他";
    }

    /** 从 uniqueId 中提取指定类型段的值，如 {@code [nested-class:Foo$Bar]} -> Foo$Bar。 */
    private String segmentValue(String uid, String segmentType) {
        String marker = "[" + segmentType + ":";
        int start = uid.indexOf(marker);
        if (start < 0) {
            return null;
        }
        String rest = uid.substring(start + marker.length());
        int end = rest.indexOf(']');
        return end < 0 ? null : rest.substring(0, end);
    }

    private String shortName(String fqcn) {
        int dot = fqcn.lastIndexOf('.');
        return dot < 0 ? fqcn : fqcn.substring(dot + 1);
    }

    @Override
    public void testPlanExecutionFinished(TestPlan testPlan) {
        System.out.println();
        System.out.println("================ 业务覆盖与用例通过情况 ================");
        int total = 0;
        int passed = 0;
        for (Map.Entry<String, int[]> e : stats.entrySet()) {
            int n = e.getValue()[0];
            int ok = e.getValue()[1];
            total += n;
            passed += ok;
            String mark = n == 0 ? " (无用例!)" : (ok == n ? " 全部通过" : " 存在失败!");
            System.out.printf("[测试覆盖] %-42s: %d/%d 通过%s%n", e.getKey(), ok, n, mark);
        }
        System.out.println("------------------------------------------------------");
        System.out.printf("[测试覆盖] 合计: %d/%d 通过%n", passed, total);
        System.out.println("======================================================");
        System.out.println();
    }
}
