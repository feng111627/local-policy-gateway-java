package com.github.feng111627.localpolicygatewayjava.policy;

import com.github.feng111627.localpolicygatewayjava.model.Policy;
import com.github.feng111627.localpolicygatewayjava.model.PolicyUpdateResult;
import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicReference;

/**
 * 持有当前生效策略的不可变引用。
 *
 * <p>{@link #replace} 通过单次原子引用赋值完成“整体生效”：并发判定线程要么读到旧版本、
 * 要么读到新版本，不可能读到只更新一半的策略。候选策略版本不大于当前版本时拒绝更新，
 * 任何失败路径都不会触碰当前引用，因此上一版完整保留。
 */
@Component
public class PolicyRepository {

    private final AtomicReference<Policy> current = new AtomicReference<>();

    public Policy current() {
        return current.get();
    }

    public boolean isEmpty() {
        return current.get() == null;
    }

    public PolicyUpdateResult replace(Policy candidate) {
        Policy active = current.get();
        if (active != null && candidate.version() <= active.version()) {
            throw new PolicyParseException(PolicyError.STALE_VERSION,
                    "候选策略版本 " + candidate.version() + " 不大于当前生效版本 " + active.version());
        }
        current.set(candidate);
        return new PolicyUpdateResult(true, candidate.version(), null,
                "策略已整体生效：" + candidate.policyId() + " v" + candidate.version());
    }
}
