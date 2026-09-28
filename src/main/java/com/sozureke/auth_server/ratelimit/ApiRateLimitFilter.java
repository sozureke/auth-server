package com.sozureke.auth_server.ratelimit;

import com.sozureke.auth_server.util.Sha256;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

/**
 * General API limit, keyed on the authenticated principal. Lives INSIDE the Basic-Auth security
 * chain, after BasicAuthenticationFilter: a key taken from the raw Authorization header would let
 * anyone burn another user's quota just by sending their email with a wrong password.
 *
 * <p>Deliberately not a bean: a Filter bean is auto-registered as a servlet filter as well, which
 * would run it a second time, outside the security chain, where there is no principal yet.
 *
 * <p>Fails open: unlike login, this limit is not what stands between an attacker and a password.
 * Unauthenticated calls are not counted here; they are rejected with 401 before doing any work.
 */
public class ApiRateLimitFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(ApiRateLimitFilter.class);

  private final RateLimiter rateLimiter;
  private final RateLimitProperties properties;
  private final RateLimitResponses responses;

  public ApiRateLimitFilter(
      RateLimiter rateLimiter, RateLimitProperties properties, ObjectMapper objectMapper) {
    this.rateLimiter = rateLimiter;
    this.properties = properties;
    this.responses = new RateLimitResponses(objectMapper);
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    return !RateLimitResponses.pathOf(request).startsWith("/api/");
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null
        || !authentication.isAuthenticated()
        || authentication instanceof AnonymousAuthenticationToken) {
      chain.doFilter(request, response);
      return;
    }

    RateLimitDecision decision = null;
    try {
      decision =
          rateLimiter.tryAcquire(
              "api:" + Sha256.hex(authentication.getName()),
              properties.api().limit(),
              properties.api().window());
    } catch (RuntimeException e) {
      log.warn("Rate limiter unavailable, letting API request through (fail-open)", e);
    }

    if (decision != null && !decision.allowed()) {
      responses.tooManyRequests(response, decision);
      return;
    }
    if (decision != null) {
      RateLimitResponses.setHeaders(response, decision);
    }
    chain.doFilter(request, response);
  }
}
