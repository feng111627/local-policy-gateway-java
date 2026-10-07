package com.github.feng111627.localpolicygatewayjava.web.dto;

import java.util.Map;

/** /access 判定请求体。 */
public class AccessRequestDto {
    private String token;
    private String resource;
    private String action;
    private Map<String, String> env;

    public String getToken() { return token; }
    public void setToken(String v) { this.token = v; }
    public String getResource() { return resource; }
    public void setResource(String v) { this.resource = v; }
    public String getAction() { return action; }
    public void setAction(String v) { this.action = v; }
    public Map<String, String> getEnv() { return env; }
    public void setEnv(Map<String, String> v) { this.env = v; }
}
