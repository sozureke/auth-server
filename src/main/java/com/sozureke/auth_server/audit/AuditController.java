package com.sozureke.auth_server.audit;

import com.sozureke.auth_server.audit.dto.AuditLogResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.time.Instant;
import org.springdoc.core.annotations.ParameterObject;
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
@Tag(name = "Admin: audit log", description = "Needs AUDIT_READ (ADMIN or AUDITOR).")
public class AuditController {

  private final AuditLogRepository auditLogRepository;

  public AuditController(AuditLogRepository auditLogRepository) {
    this.auditLogRepository = auditLogRepository;
  }

  @GetMapping
  @PreAuthorize("hasAuthority('AUDIT_READ')")
  @Operation(
      summary = "Search the audit log",
      description = "All filters are optional and combined with AND. Newest first by default.")
  @ApiResponse(responseCode = "200", description = "Page of audit entries")
  @ApiResponse(responseCode = "400", description = "Invalid filter value")
  public Page<AuditLogResponse> list(
      @Parameter(description = "Actor user id") @RequestParam(required = false) Long userId,
      @RequestParam(required = false) AuditEventType action,
      @Parameter(description = "ISO-8601 instant, inclusive")
          @RequestParam(required = false)
          @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
          Instant from,
      @Parameter(description = "ISO-8601 instant, inclusive")
          @RequestParam(required = false)
          @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
          Instant to,
      @ParameterObject
          @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC)
          Pageable pageable) {
    return auditLogRepository
        .search(userId, action == null ? null : action.name(), from, to, pageable)
        .map(AuditLogResponse::from);
  }
}
