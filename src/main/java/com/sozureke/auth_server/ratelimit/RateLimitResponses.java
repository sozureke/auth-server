package com.sozureke.auth_server.ratelimit;

import com.sozureke.auth_server.config.ApiError;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.springframework.http.MediaType;
import tools.jackson.databind.ObjectMapper;

/** Response side shared by the rate-limit filters. */
final class RateLimitResponses {

  private final ObjectMapper objectMapper;

  RateLimitResponses(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  // servletPath + pathInfo, not the raw URI: the container has already decoded and normalised
  // both (path parameters like ";jsessionid=x" are stripped), so those can't be used to dodge a
  // limit. Which of the two carries the path depends on how the servlet is mapped.
  static String pathOf(HttpServletRequest request) {
    String pathInfo = request.getPathInfo();
    return request.getServletPath() + (pathInfo != null ? pathInfo : "");
  }

  // X-RateLimit-Reset is relative: seconds until a slot frees up (not an epoch timestamp).
  static void setHeaders(HttpServletResponse response, RateLimitDecision decision) {
    response.setHeader("X-RateLimit-Limit", String.valueOf(decision.limit()));
    response.setHeader("X-RateLimit-Remaining", String.valueOf(decision.remaining()));
    response.setHeader("X-RateLimit-Reset", String.valueOf(decision.resetSeconds()));
  }

  void tooManyRequests(HttpServletResponse response, RateLimitDecision decision)
      throws IOException {
    setHeaders(response, decision);
    response.setHeader("Retry-After", String.valueOf(Math.max(1, decision.resetSeconds())));
    error(response, 429, "Too many requests, retry in " + decision.resetSeconds() + "s");
  }

  // Written straight to the response: sendError() triggers an /error dispatch that falls outside
  // the security matchers and turns the status into a misleading 401.
  void error(HttpServletResponse response, int status, String message) throws IOException {
    response.setStatus(status);
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
    response
        .getWriter()
        .write(objectMapper.writeValueAsString(new ApiError(status, message, null)));
  }
}
