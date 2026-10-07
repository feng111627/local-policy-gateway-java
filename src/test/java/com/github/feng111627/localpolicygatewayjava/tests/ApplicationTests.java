package com.github.feng111627.localpolicygatewayjava.tests;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * 上下文冒烟测试。密钥库与策略文件定向到 target/ 下，避免测试污染源码树根目录。
 */
@SpringBootTest(properties = {
        "gateway.policy-file=target/test-policies/smoke-policy.json",
        "gateway.key-store-file=target/test-keystores/smoke-keystore.json"
})
public class ApplicationTests {
    @Test
    public void contentLoad() {
    }
}
