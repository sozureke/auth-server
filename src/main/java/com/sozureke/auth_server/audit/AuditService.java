package com.sozureke.auth_server.audit;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Service
public class AuditService {

  private final AuditLogRepository auditLogRepository;

  public AuditService(AuditLogRepository auditLogRepository) {
    this.auditLogRepository = auditLogRepository;
  }

  /**
   * REQUIRES_NEW: audit rows must survive a rollback of whatever transaction the caller is in.
   * Without this, a failed login (the event we most need on record) rolls back together with the
   * business operation that failed — caught live, not from a code review: a wrong-password attempt
   * produced no LOGIN_FAILED row even though this method was reached and ran.
   */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void log(
      Long userId,
      AuditEventType action,
      String entityType,
      String entityId,
      Map<String, Object> details) {
    auditLogRepository.save(
        new AuditLog(
            userId, action, entityType, entityId, currentIpAddress(), currentUserAgent(), details));
  }

  private static String currentIpAddress() {
    HttpServletRequest request = currentRequest();
    return request == null ? null : request.getRemoteAddr();
  }

  private static String currentUserAgent() {
    HttpServletRequest request = currentRequest();
    return request == null ? null : request.getHeader("User-Agent");
  }

  private static HttpServletRequest currentRequest() {
    RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
    return attributes instanceof ServletRequestAttributes servletRequestAttributes
        ? servletRequestAttributes.getRequest()
        : null;
  }
}
