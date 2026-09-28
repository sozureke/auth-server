package com.sozureke.auth_server.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;

/** Runs against the real Redis from docker-compose: the Lua script is the thing under test. */
@SpringBootTest
class RateLimiterTest {

  private static final Duration WINDOW = Duration.ofSeconds(1);

  @Autowired private RateLimiter rateLimiter;
  @Autowired private StringRedisTemplate redisTemplate;

  private final String key = "test-" + UUID.randomUUID();

  @AfterEach
  void cleanUp() {
    redisTemplate.delete("rate-limit:" + key);
  }

  @Test
  void allowsUpToTheLimit_thenDenies() {
    for (int i = 0; i < 3; i++) {
      assertThat(rateLimiter.tryAcquire(key, 3, WINDOW).allowed()).as("request %d", i).isTrue();
    }

    assertThat(rateLimiter.tryAcquire(key, 3, WINDOW).allowed()).isFalse();
  }

  @Test
  void remainingCountsDown_andReportsLimit() {
    RateLimitDecision first = rateLimiter.tryAcquire(key, 3, WINDOW);
    RateLimitDecision second = rateLimiter.tryAcquire(key, 3, WINDOW);
    RateLimitDecision third = rateLimiter.tryAcquire(key, 3, WINDOW);
    RateLimitDecision denied = rateLimiter.tryAcquire(key, 3, WINDOW);

    assertThat(first.remaining()).isEqualTo(2);
    assertThat(second.remaining()).isEqualTo(1);
    assertThat(third.remaining()).isZero();
    assertThat(denied.remaining()).isZero();
    assertThat(denied.limit()).isEqualTo(3);
  }

  @Test
  void deniedRequestsReportWhenASlotFreesUp() {
    Duration window = Duration.ofSeconds(30);
    rateLimiter.tryAcquire(key, 1, window);

    RateLimitDecision denied = rateLimiter.tryAcquire(key, 1, window);

    assertThat(denied.allowed()).isFalse();
    assertThat(denied.resetSeconds()).isBetween(28L, 30L);
  }

  @Test
  void keysAreIndependent() {
    String other = key + "-other";
    try {
      rateLimiter.tryAcquire(key, 1, WINDOW);

      assertThat(rateLimiter.tryAcquire(key, 1, WINDOW).allowed()).isFalse();
      assertThat(rateLimiter.tryAcquire(other, 1, WINDOW).allowed()).isTrue();
    } finally {
      redisTemplate.delete("rate-limit:" + other);
    }
  }

  @Test
  void allowsAgainOnceTheWindowHasPassed() throws InterruptedException {
    rateLimiter.tryAcquire(key, 1, WINDOW);
    assertThat(rateLimiter.tryAcquire(key, 1, WINDOW).allowed()).isFalse();

    Thread.sleep(1200);

    assertThat(rateLimiter.tryAcquire(key, 1, WINDOW).allowed()).isTrue();
  }

  // The reason this is a sliding window and not a fixed one: with a fixed window aligned to the
  // first request, the whole quota would come back at t=1.0s. Here request B (t=0.7s) is still
  // inside the window at t=1.1s, so only ONE slot has been freed, not both.
  @Test
  void window_slides_insteadOfResettingAllAtOnce() throws InterruptedException {
    rateLimiter.tryAcquire(key, 2, WINDOW); // A at t=0
    Thread.sleep(700);
    rateLimiter.tryAcquire(key, 2, WINDOW); // B at t=0.7
    Thread.sleep(400); // t=1.1: A expired, B still counts

    RateLimitDecision afterA = rateLimiter.tryAcquire(key, 2, WINDOW);
    RateLimitDecision next = rateLimiter.tryAcquire(key, 2, WINDOW);

    assertThat(afterA.allowed()).isTrue();
    assertThat(afterA.remaining()).isZero();
    assertThat(next.allowed()).isFalse();
  }

  @Test
  void idleKeysExpireFromRedis() throws InterruptedException {
    rateLimiter.tryAcquire(key, 5, Duration.ofMillis(500));
    assertThat(redisTemplate.hasKey("rate-limit:" + key)).isTrue();

    Thread.sleep(800);

    assertThat(redisTemplate.hasKey("rate-limit:" + key)).isFalse();
  }
}
