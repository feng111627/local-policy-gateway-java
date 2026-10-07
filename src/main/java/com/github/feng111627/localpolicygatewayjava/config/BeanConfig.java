package com.github.feng111627.localpolicygatewayjava.config;

import com.github.feng111627.localpolicygatewayjava.auth.KeyStore;
import com.github.feng111627.localpolicygatewayjava.auth.TokenService;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyAdminService;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 本地组件装配：
 * 密钥库启动时从受完整性保护的本地文件加载（不存在则引导首把密钥），
 * 策略文件若存在则整版加载，若不存在则保持“无策略 = 默认拒绝”。
 */
@Configuration
@EnableConfigurationProperties(GatewayProperties.class)
public class BeanConfig {

    private static final Logger log = LoggerFactory.getLogger(BeanConfig.class);

    @Bean
    public KeyStore keyStore(GatewayProperties props) {
        Path path = Paths.get(props.getKeyStoreFile());
        KeyStore store = new KeyStore(path);
        store.load();
        log.info("本地密钥库已加载: {} (ACTIVE={}, 总密钥数={})",
                path, store.activeKey().kid(), store.all().size());
        return store;
    }

    @Bean
    public TokenService tokenService(KeyStore keyStore) {
        return new TokenService(keyStore);
    }

    @Bean
    public PolicyEngine policyEngine() {
        return new PolicyEngine();
    }

    @Bean
    public PolicyAdminService policyAdminService(PolicyEngine engine) {
        return new PolicyAdminService(engine);
    }

    @Bean
    public org.springframework.boot.ApplicationRunner policyBootstrap(
            GatewayProperties props, PolicyAdminService admin) {
        return args -> {
            Path policyPath = Paths.get(props.getPolicyFile());
            if (java.nio.file.Files.exists(policyPath)) {
                PolicyAdminService.UpdateResult r = admin.reloadFromFile(policyPath);
                if (r.applied()) {
                    log.info("启动加载策略成功: {}", r.version());
                } else {
                    log.warn("启动策略加载失败，系统保持默认拒绝: reason={}, detail={}",
                            r.reason(), r.detail());
                }
            } else {
                log.warn("未找到策略文件 {}，当前无生效策略，所有请求默认拒绝", policyPath);
            }
        };
    }
}
