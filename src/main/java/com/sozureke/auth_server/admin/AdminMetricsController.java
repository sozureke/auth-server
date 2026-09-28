package com.sozureke.auth_server.admin;

import com.sozureke.auth_server.admin.dto.AdminSessionSummary;
import com.sozureke.auth_server.admin.dto.MetricsResponse;
import com.sozureke.auth_server.audit.AuditEventType;
import com.sozureke.auth_server.audit.AuditLogRepository;
import com.sozureke.auth_server.user.UserRepository;
import java.time.Duration;
import java.time.Instant;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasAuthority('USER_READ')")
public class AdminMetricsController {

  private final UserRepository userRepository;
  private final AuditLogRepository auditLogRepository;
  private final AdminSessionService adminSessionService;

  public AdminMetricsController(
      UserRepository userRepository,
      AuditLogRepository auditLogRepository,
      AdminSessionService adminSessionService) {
    this.userRepository = userRepository;
    this.auditLogRepository = auditLogRepository;
    this.adminSessionService = adminSessionService;
  }

  @GetMapping("/sessions")
  public Page<AdminSessionSummary> sessions(@PageableDefault(size = 20) Pageable pageable) {
    return adminSessionService.list(pageable);
  }

  @GetMapping("/metrics")
  public MetricsResponse metrics() {
    Instant since = Instant.now().minus(Duration.ofHours(24));
    return new MetricsResponse(
        userRepository.count(),
        adminSessionService.count(),
        auditLogRepository.countByActionAndCreatedAtAfter(
            AuditEventType.LOGIN_FAILED.name(), since));
  }
}
