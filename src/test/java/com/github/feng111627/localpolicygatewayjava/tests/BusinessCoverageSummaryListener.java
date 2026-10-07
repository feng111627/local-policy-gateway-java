package com.github.feng111627.localpolicygatewayjava.tests;

import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 测试业务覆盖汇总监听器。
 *
 * <p>测试运行结束后输出一张“业务主线 → 用例数 / 通过 / 失败 / 跳过”的汇总表，
 * 让 {@code mvn test} 日志能直接看出覆盖了哪些业务、各业务用例数量与通过情况。
 * 业务分组取自顶层测试类上的 {@code @DisplayName}（@Nested 内层类继承外层业务名）。
 */
public class BusinessCoverageSummaryListener implements TestExecutionListener {

    private static final String PREFIX = "[测试覆盖汇总] ";

    private final Map<String, Counters> byBusiness = new LinkedHashMap<>();
    /** 每个用例 UID 归属的业务名，构建测试树时一次性确定。 */
    private final Map<String, String> businessOfTest = new LinkedHashMap<>();

    private record Counters(AtomicInteger total, AtomicInteger passed, AtomicInteger failed,
                            AtomicInteger skipped) {
        Counters() {
            this(new AtomicInteger(), new AtomicInteger(), new AtomicInteger(), new AtomicInteger());
        }
    }

    @Override
    public void testPlanExecutionStarted(TestPlan testPlan) {
        byBusiness.clear();
        businessOfTest.clear();
        for (TestIdentifier root : testPlan.getRoots()) {
            walk(testPlan, root, null);
        }
        System.out.println();
        System.out.println(PREFIX + "========== 测试会话开始 ==========");
    }

    /**
     * 深度遍历测试树：
     * <ul>
     *   <li>遇到顶层测试类（含 [class: 但不含 [nested-class:）→ 它的 DisplayName 即业务名；</li>
     *   <li>业务名沿树向下传递，@Nested 内层类及其用例都归属于该业务；</li>
     *   <li>真正的测试方法登记到 businessOfTest。</li>
     * </ul>
     */
    private void walk(TestPlan plan, TestIdentifier node, String inheritedBusiness) {
        String business = inheritedBusiness;
        String uid = node.getUniqueId();
        // 业务分组节点：容器节点里，排除引擎根与 @Nested 内层类，其余顶层测试类/配置类均算业务类。
        if (!node.isTest() && uid.contains("[class:") && !uid.contains("[nested-class:")) {
            business = node.getDisplayName();
            byBusiness.putIfAbsent(business, new Counters());
        }
        if (node.isTest() && business != null) {
            businessOfTest.put(uid, business);
        }
        for (TestIdentifier child : plan.getChildren(uid)) {
            walk(plan, child, business);
        }
    }

    @Override
    public void executionFinished(TestIdentifier testIdentifier, TestExecutionResult result) {
        if (!testIdentifier.isTest()) {
            return;
        }
        Counters counters = byBusiness.computeIfAbsent(businessOf(testIdentifier), k -> new Counters());
        counters.total().incrementAndGet();
        switch (result.getStatus()) {
            case SUCCESSFUL -> counters.passed().incrementAndGet();
            case FAILED -> counters.failed().incrementAndGet();
            case ABORTED -> counters.skipped().incrementAndGet();
        }
    }

    @Override
    public void executionSkipped(TestIdentifier testIdentifier, String reason) {
        if (!testIdentifier.isTest()) {
            return;
        }
        Counters counters = byBusiness.computeIfAbsent(businessOf(testIdentifier), k -> new Counters());
        counters.total().incrementAndGet();
        counters.skipped().incrementAndGet();
    }

    private String businessOf(TestIdentifier id) {
        return businessOfTest.getOrDefault(id.getUniqueId(), "其他");
    }

    @Override
    public void testPlanExecutionFinished(TestPlan testPlan) {
        int grandTotal = 0;
        int grandPassed = 0;
        int grandFailed = 0;
        int grandSkipped = 0;
        StringBuilder out = new StringBuilder();
        out.append(System.lineSeparator());
        out.append(PREFIX).append("====== 业务覆盖与通过情况 ======").append(System.lineSeparator());
        for (Map.Entry<String, Counters> entry : byBusiness.entrySet()) {
            Counters c = entry.getValue();
            grandTotal += c.total().get();
            grandPassed += c.passed().get();
            grandFailed += c.failed().get();
            grandSkipped += c.skipped().get();
            out.append(PREFIX)
                    .append(String.format("%-44s 用例 %2d | 通过 %2d | 失败 %d | 跳过 %d",
                            entry.getKey(), c.total().get(), c.passed().get(),
                            c.failed().get(), c.skipped().get()))
                    .append(System.lineSeparator());
        }
        out.append(PREFIX).append("----------------------------------------------").append(System.lineSeparator());
        out.append(PREFIX)
                .append(String.format("合计：业务 %d 项，用例 %d，通过 %d，失败 %d，跳过 %d",
                        byBusiness.size(), grandTotal, grandPassed, grandFailed, grandSkipped))
                .append(System.lineSeparator());
        out.append(PREFIX).append(grandFailed == 0
                ? "结论：全部业务用例通过 ✅" : "结论：存在失败用例 ❌")
                .append(System.lineSeparator());
        out.append(PREFIX).append("==============================================").append(System.lineSeparator());
        System.out.println(out);
    }
}
