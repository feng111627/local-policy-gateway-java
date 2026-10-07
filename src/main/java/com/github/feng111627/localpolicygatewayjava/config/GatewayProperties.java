package com.github.feng111627.localpolicygatewayjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** 本地文件路径等配置。 */
@ConfigurationProperties(prefix = "gateway")
public class GatewayProperties {

    private String policyFile;
    private String keyStoreFile;
    private String issuer;
    private long rotationOverlapMillis;

    public String getPolicyFile() { return policyFile; }
    public void setPolicyFile(String v) { this.policyFile = v; }
    public String getKeyStoreFile() { return keyStoreFile; }
    public void setKeyStoreFile(String v) { this.keyStoreFile = v; }
    public String getIssuer() { return issuer; }
    public void setIssuer(String v) { this.issuer = v; }
    public long getRotationOverlapMillis() { return rotationOverlapMillis; }
    public void setRotationOverlapMillis(long v) { this.rotationOverlapMillis = v; }
}
