package com.github.feng111627.localpolicygatewayjava.tests;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/** Spring 上下文装配冒烟：保证默认策略、密钥库等 Bean 能正常启动。 */
@SpringBootTest
@DisplayName("冒烟：Spring 上下文装配与默认策略启动")
class ApplicationTests {

    @Test
    @DisplayName("用例0.1 应用上下文可启动且默认策略装载成功")
    void contextLoadsWithDefaultPolicy() {
    }
}
