package com.sozureke.auth_server.audit;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.Map;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "audit_log")
@Getter
@NoArgsConstructor
public class AuditLog {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "user_id")
  private Long userId;

  @Column(nullable = false, length = 50)
  private String action;

  @Column(name = "entity_type", length = 50)
  private String entityType;

  @Column(name = "entity_id", length = 100)
  private String entityId;

  @Column(name = "ip_address", length = 45)
  private String ipAddress;

  @Column(name = "user_agent")
  private String userAgent;

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(columnDefinition = "jsonb")
  private Map<String, Object> details;

  @Column(name = "created_at", nullable = false, updatable = false)
  private Instant createdAt = Instant.now();

  public AuditLog(
      Long userId,
      AuditEventType action,
      String entityType,
      String entityId,
      String ipAddress,
      String userAgent,
      Map<String, Object> details) {
    this.userId = userId;
    this.action = action.name();
    this.entityType = entityType;
    this.entityId = entityId;
    this.ipAddress = ipAddress;
    this.userAgent = userAgent;
    this.details = details;
  }
}
