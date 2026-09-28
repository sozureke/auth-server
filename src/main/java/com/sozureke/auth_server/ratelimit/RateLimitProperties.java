package com.sozureke.auth_server.ratelimit;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Defaults are the limits from the spec; tests override them with short windows. */
@ConfigurationProperties(prefix = "app.rate-limit")
public record RateLimitProperties(Rule login, Rule loginIp, Rule register, Rule token, Rule api) {

  public record Rule(int limit, Duration window) {}

  public RateLimitProperties {
    login = login != null ? login : new Rule(5, Duration.ofMinutes(15));
    loginIp = loginIp != null ? loginIp : new Rule(20, Duration.ofMinutes(15));
    register = register != null ? register : new Rule(3, Duration.ofHours(1));
    token = token != null ? token : new Rule(10, Duration.ofMinutes(1));
    api = api != null ? api : new Rule(100, Duration.ofMinutes(1));
  }
}
