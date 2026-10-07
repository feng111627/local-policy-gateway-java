package com.github.feng111627.localpolicygatewayjava.policy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 策略热更新服务。
 *
 * <p>事务语义：先在局部完成全部解析与校验，{@link PolicyEngine#replace(Policy)}
 * 只是一次引用发布——要么整版生效，要么整版不生效；解析阶段抛异常时旧版本原封不动，
 * 并发判定线程不可能看到半成品。
 */
public class PolicyAdminService {

    private static final Logger log = LoggerFactory.getLogger(PolicyAdminService.class);

    private final PolicyEngine engine;
    private final PolicyParser parser = new PolicyParser();

    public PolicyAdminService(PolicyEngine engine) {
        this.engine = engine;
    }

    /** 用 JSON 文本整版替换当前策略。 */
    public synchronized UpdateResult apply(String json) {
        Policy previous = engine.current();
        Policy candidate;
        try {
            candidate = parser.parse(json);
        } catch (PolicyLoadException e) {
            log.warn("策略热更新被拒绝，保留旧版本 {}: reason={}, detail={}",
                    previous == null ? "<none>" : previous.version(),
                    e.reason(), e.getMessage());
            return new UpdateResult(false,
                    previous == null ? null : previous.version(),
                    e.reason().name(), e.getMessage());
        }
        engine.replace(candidate);
        log.info("策略热更新整体生效: {} -> {}",
                previous == null ? "<none>" : previous.version(), candidate.version());
        return new UpdateResult(true, candidate.version(), null,
                "已整体生效，规则数=" + candidate.rules().size());
    }

    /** 从文件重新加载（同样具备原子与失败保留语义）。 */
    public UpdateResult reloadFromFile(Path file) {
        try {
            return apply(Files.readString(file, StandardCharsets.UTF_8));
        } catch (Exception e) {
            Policy previous = engine.current();
            return new UpdateResult(false,
                    previous == null ? null : previous.version(),
                    PolicyLoadFailure.SYNTAX_ERROR.name(), "策略文件读取失败: " + e.getMessage());
        }
    }

    /** 热更新结果。 */
    public record UpdateResult(boolean applied, String version, String reason, String detail) {
    }
}
