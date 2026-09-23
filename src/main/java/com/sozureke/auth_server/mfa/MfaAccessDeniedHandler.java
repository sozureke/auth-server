package com.sozureke.auth_server.mfa;

import com.sozureke.auth_server.auth.AuthUserDetails;
import com.sozureke.auth_server.config.ApiError;
import com.sozureke.auth_server.user.User;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.savedrequest.RequestCache;
import tools.jackson.databind.ObjectMapper;

/**
 * Only registered for {@code /oauth2/authorize}: an ADMIN without a verified TOTP session lands
 * here. Enrolled admins are sent to the TOTP form with the original request preserved; admins who
 * never enrolled have nothing to verify, so they get a plain 403 instead of a redirect loop.
 *
 * <p>Responses are written directly rather than via {@code sendError()}: {@code sendError()}
 * triggers a container error dispatch to {@code /error}, which falls outside this filter chain's
 * securityMatcher and lands in the Basic-Auth-protected default chain instead, turning our 403 into
 * a misleading 401.
 */
public class MfaAccessDeniedHandler implements AccessDeniedHandler {

  private final RequestCache requestCache;
  private final ObjectMapper objectMapper;

  public MfaAccessDeniedHandler(RequestCache requestCache, ObjectMapper objectMapper) {
    this.requestCache = requestCache;
    this.objectMapper = objectMapper;
  }

  @Override
  public void handle(
      HttpServletRequest request, HttpServletResponse response, AccessDeniedException ex)
      throws IOException, ServletException {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (!(authentication.getPrincipal() instanceof AuthUserDetails principal)) {
      writeJsonError(response, HttpServletResponse.SC_FORBIDDEN, "Access denied");
      return;
    }

    User user = principal.getUser();
    if (!user.isMfaEnabled()) {
      writeJsonError(
          response,
          HttpServletResponse.SC_FORBIDDEN,
          "MFA enrollment is required for admin accounts");
      return;
    }

    requestCache.saveRequest(request, response);
    response.sendRedirect(request.getContextPath() + "/login/totp");
  }

  private void writeJsonError(HttpServletResponse response, int status, String message)
      throws IOException {
    response.setStatus(status);
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response
        .getWriter()
        .write(objectMapper.writeValueAsString(new ApiError(status, message, null)));
  }
}
