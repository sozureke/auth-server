package com.sozureke.auth_server.session;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.RequestCache;

public class SessionMetadataAuthenticationSuccessHandler
    extends SavedRequestAwareAuthenticationSuccessHandler {
  public SessionMetadataAuthenticationSuccessHandler(RequestCache requestCache) {
    setRequestCache(requestCache);
  }

  @Override
  public void onAuthenticationSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws ServletException, IOException {
    request.getSession().setAttribute("ipAddress", request.getRemoteAddr());
    request.getSession().setAttribute("userAgent", request.getHeader("User-Agent"));
    super.onAuthenticationSuccess(request, response, authentication);
  }
}
