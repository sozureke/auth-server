package com.sozureke.auth_server.mfa;

import com.sozureke.auth_server.auth.AuthUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import java.util.function.Supplier;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

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
    boolean mfaEnrolled =
        auth.getPrincipal() instanceof AuthUserDetails details && details.getUser().isMfaEnabled();
    if (!isAdmin && !mfaEnrolled) {
      return new AuthorizationDecision(true);
    }

    HttpServletRequest request = context.getRequest();
    return new AuthorizationDecision(MfaSession.isVerified(request.getSession(false)));
  }
}
