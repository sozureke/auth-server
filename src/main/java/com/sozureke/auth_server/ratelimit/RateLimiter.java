package com.sozureke.auth_server.ratelimit;

import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

@Component
public class RateLimiter {

  private static final String KEY_PREFIX = "rate-limit:";

  private final StringRedisTemplate redisTemplate;

  @SuppressWarnings("rawtypes") // setResultType(Class<T>) cannot express List<Long>
  private final DefaultRedisScript<List> script;

  public RateLimiter(StringRedisTemplate redisTemplate) {
    this.redisTemplate = redisTemplate;
    this.script = new DefaultRedisScript<>();
    this.script.setLocation(new ClassPathResource("redis/sliding-window-rate-limit.lua"));
    this.script.setResultType(List.class);
  }

  public RateLimitDecision tryAcquire(String key, int limit, Duration window) {
    List<?> result =
        redisTemplate.execute(
            script,
            List.of(KEY_PREFIX + key),
            String.valueOf(limit),
            String.valueOf(window.toMillis()),
            UUID.randomUUID().toString());
    if (result == null || result.size() != 3) {
      throw new IllegalStateException("Unexpected rate limiter script result: " + result);
    }
    long allowed = ((Number) result.get(0)).longValue();
    long remaining = ((Number) result.get(1)).longValue();
    long resetMs = ((Number) result.get(2)).longValue();
    return new RateLimitDecision(allowed == 1, limit, remaining, (resetMs + 999) / 1000);
  }
}
