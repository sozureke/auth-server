package com.sozureke.auth_server.admin.dto;

import java.time.Instant;

public record AdminSessionSummary(
    String id,
    String principal,
    String ipAddress,
    String userAgent,
    Instant createdAt,
    Instant lastAccessedAt) {}
