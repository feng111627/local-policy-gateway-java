package com.github.feng111627.localpolicygatewayjava.config;

import com.github.feng111627.localpolicygatewayjava.model.Policy;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyParseException;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyParser;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyRepository;
import com.github.feng111627.localpolicygatewayjava.policy.PolicyValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * 启动时加载 classpath:policies/default-policy.json 作为第一版生效策略。
 * 默认策略必须合法：若连内置默认策略都无法解析/校验，直接让启动失败，绝不带空策略放行。
 */
@Component
public class GatewayInitializer implements ApplicationRunner {

    static final String DEFAULT_POLICY_LOCATION = "policies/default-policy.json";

    private final PolicyRepository repository;
    private final PolicyParser parser;
    private final PolicyValidator validator;

    @Autowired
    public GatewayInitializer(PolicyRepository repository, PolicyParser parser, PolicyValidator validator) {
        this.repository = repository;
        this.parser = parser;
        this.validator = validator;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!repository.isEmpty()) {
            return;
        }
        Policy policy = parser.parse(loadDefaultPolicyJson());
        validator.validate(policy);
        try {
            repository.replace(policy);
        } catch (PolicyParseException e) {
            throw new IllegalStateException("内置默认策略无法装载: " + e.getMessage(), e);
        }
    }

    static String loadDefaultPolicyJson() {
        try (InputStream in = new ClassPathResource(DEFAULT_POLICY_LOCATION).getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("找不到内置默认策略 " + DEFAULT_POLICY_LOCATION, e);
        }
    }
}
