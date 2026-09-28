package com.sozureke.auth_server.ratelimit;

public record RateLimitDecision(boolean allowed, long limit, long remaining, long resetSeconds) {}
