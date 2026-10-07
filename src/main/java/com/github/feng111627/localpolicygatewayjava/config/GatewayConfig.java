package com.github.feng111627.localpolicygatewayjava.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/** 通用 Bean 配置：统一时钟，便于测试时间相关逻辑。 */
@Configuration
public class GatewayConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
