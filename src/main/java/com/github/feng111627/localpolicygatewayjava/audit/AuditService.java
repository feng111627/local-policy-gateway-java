package com.github.feng111627.localpolicygatewayjava.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 审计服务：每次判定都追加一条结构化审计记录（日志 + 内存最近记录）。
 * 使用 {@link CopyOnWriteArrayList}，并发判定下追加与读取互不阻塞、不丢记录。
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger("AUDIT");

    private final List<AuditRecord> records = new CopyOnWriteArrayList<>();
    private final int retainLimit;

    public AuditService() {
        this(10_000);
    }

    public AuditService(int retainLimit) {
        this.retainLimit = retainLimit;
    }

    public void record(AuditRecord r) {
        records.add(r);
        while (records.size() > retainLimit) {
            records.remove(0);
        }
        log.info("AUDIT requestId={} subject={} role={} resource={} action={} outcome={} reason={} rule={} policyVersion={} kid={}",
                r.requestId(), r.subject(), r.role(), r.resource(), r.action(),
                r.outcome(), r.reasonCode(),
                r.matchedRuleId() == null ? "-" : r.matchedRuleId(),
                r.policyVersion() == null ? "-" : r.policyVersion(),
                r.kid() == null ? "-" : r.kid());
    }

    public List<AuditRecord> recent() {
        return List.copyOf(records);
    }
}
