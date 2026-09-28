package com.sozureke.auth_server.audit;

import java.time.Instant;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

  @Query(
      """
            SELECT a FROM AuditLog a
            WHERE (CAST(:userId AS long) IS NULL OR a.userId = :userId)
              AND (CAST(:action AS string) IS NULL OR a.action = :action)
              AND (CAST(:from AS timestamp) IS NULL OR a.createdAt >= :from)
              AND (CAST(:to AS timestamp) IS NULL OR a.createdAt <= :to)
            """)
  Page<AuditLog> search(
      @Param("userId") Long userId,
      @Param("action") String action,
      @Param("from") Instant from,
      @Param("to") Instant to,
      Pageable pageable);
}
