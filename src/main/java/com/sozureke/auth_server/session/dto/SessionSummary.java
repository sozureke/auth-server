package com.sozureke.auth_server.session.dto;

import java.time.Instant;

public record SessionSummary(
    String id,
    boolean current,
    String ipAddress,
    String userAgent,
    Instant createdAt,
    Instant lastAccessedAt) {}
