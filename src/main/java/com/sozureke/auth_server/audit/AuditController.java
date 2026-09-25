package com.sozureke.auth_server.audit;

import com.sozureke.auth_server.audit.dto.AuditLogResponse;
import java.time.Instant;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/audit")
public class AuditController {

  private final AuditLogRepository auditLogRepository;

  public AuditController(AuditLogRepository auditLogRepository) {
    this.auditLogRepository = auditLogRepository;
  }

  @GetMapping
  @PreAuthorize("hasAuthority('AUDIT_READ')")
  public Page<AuditLogResponse> list(
      @RequestParam(required = false) Long userId,
      @RequestParam(required = false) AuditEventType action,
      @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
          Instant from,
      @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
          Instant to,
      @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC)
          Pageable pageable) {
    return auditLogRepository
        .search(userId, action == null ? null : action.name(), from, to, pageable)
        .map(AuditLogResponse::from);
  }
}
