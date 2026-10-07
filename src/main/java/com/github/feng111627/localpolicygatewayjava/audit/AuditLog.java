package com.github.feng111627.localpolicygatewayjava.audit;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * 审计记录存储：每次判定都追加一条可追溯记录。
 * 默认内存实现，保留最近 {@value #MAX_EVENTS} 条，线程安全。
 */
@Component
public class AuditLog {

    static final int MAX_EVENTS = 1000;

    private final ConcurrentLinkedDeque<AuditEvent> events = new ConcurrentLinkedDeque<>();

    public void record(AuditEvent event) {
        events.addLast(event);
        while (events.size() > MAX_EVENTS) {
            events.pollFirst();
        }
    }

    public List<AuditEvent> events() {
        return Collections.unmodifiableList(new ArrayList<>(events));
    }

    public void clear() {
        events.clear();
    }
}
