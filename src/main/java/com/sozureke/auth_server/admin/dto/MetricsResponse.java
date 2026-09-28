package com.sozureke.auth_server.admin.dto;

public record MetricsResponse(long totalUsers, long activeSessions, long failedLoginsLast24h) {}
