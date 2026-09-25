package com.sozureke.auth_server.audit.dto;

import com.sozureke.auth_server.audit.AuditLog;
import java.time.Instant;
import java.util.Map;

public record AuditLogResponse(
    Long id,
    Long userId,
    String action,
    String entityType,
    String entityId,
    String ipAddress,
    String userAgent,
    Map<String, Object> details,
    Instant createdAt) {

  public static AuditLogResponse from(AuditLog log) {
    return new AuditLogResponse(
        log.getId(),
        log.getUserId(),
        log.getAction(),
        log.getEntityType(),
        log.getEntityId(),
        log.getIpAddress(),
        log.getUserAgent(),
        log.getDetails(),
        log.getCreatedAt());
  }
}
