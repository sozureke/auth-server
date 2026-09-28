package com.sozureke.auth_server.audit;

import com.sozureke.auth_server.auth.AuthUserDetails;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

/** Audits LOGOUT before delegating to the default redirect behavior. */
public class AuditingLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

  private final AuditService auditService;

  public AuditingLogoutSuccessHandler(AuditService auditService) {
    this.auditService = auditService;
    setDefaultTargetUrl("/login?logout");
  }

  @Override
  public void onLogoutSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException, ServletException {
    if (authentication != null
        && authentication.getPrincipal() instanceof AuthUserDetails principal) {
      Long userId = principal.getUser().getId();
      auditService.log(userId, AuditEventType.LOGOUT, "user", userId.toString(), null);
    }
    super.onLogoutSuccess(request, response, authentication);
  }
}
