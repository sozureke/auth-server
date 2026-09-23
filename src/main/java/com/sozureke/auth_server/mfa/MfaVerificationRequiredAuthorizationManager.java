package com.sozureke.auth_server.mfa;

import jakarta.servlet.http.HttpServletRequest;
import java.util.function.Supplier;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * Gates a request behind a verified TOTP session for ADMIN accounts. Enrollment status is not
 * checked here (that distinction belongs to {@link MfaAccessDeniedHandler}, which decides whether
 * to redirect to the TOTP form or report that enrollment itself is missing) — an ADMIN without a
 * verified session is denied either way.
 */
public class MfaVerificationRequiredAuthorizationManager
    implements AuthorizationManager<RequestAuthorizationContext> {

  private static final String ADMIN_AUTHORITY = "ROLE_ADMIN";

  @Override
  public AuthorizationResult authorize(
      Supplier<? extends Authentication> authentication, RequestAuthorizationContext context) {
    Authentication auth = authentication.get();
    boolean isAdmin =
        auth.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .anyMatch(ADMIN_AUTHORITY::equals);
    if (!isAdmin) {
      return new AuthorizationDecision(true);
    }

    HttpServletRequest request = context.getRequest();
    return new AuthorizationDecision(MfaSession.isVerified(request.getSession(false)));
  }
}
