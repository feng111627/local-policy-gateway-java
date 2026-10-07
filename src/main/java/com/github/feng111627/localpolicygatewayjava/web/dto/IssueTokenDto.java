package com.github.feng111627.localpolicygatewayjava.web.dto;

/** 本地演示用令牌签发请求。 */
public class IssueTokenDto {
    private String subject;
    private String role;
    private long ttlMillis = 3_600_000L;

    public String getSubject() { return subject; }
    public void setSubject(String v) { this.subject = v; }
    public String getRole() { return role; }
    public void setRole(String v) { this.role = v; }
    public long getTtlMillis() { return ttlMillis; }
    public void setTtlMillis(long v) { this.ttlMillis = v; }
}
