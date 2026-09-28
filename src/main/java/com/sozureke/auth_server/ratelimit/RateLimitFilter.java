package com.sozureke.auth_server.ratelimit;

import com.sozureke.auth_server.util.Sha256;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Rate limits the unauthenticated, brute-force-prone endpoints. Registered explicitly (see
 * RateLimitConfig) and deliberately NOT a @Component: component filters get the lowest precedence,
 * i.e. they would run after Spring Security and never see the requests it rejects.
 *
 * <p>Keys use getRemoteAddr(): behind a reverse proxy every client would share one address, and
 * trusting X-Forwarded-For blindly lets callers dodge the limit by spoofing it (tracked as
 * deployment hardening).
 */
public class RateLimitFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(RateLimitFilter.class);
  private static final int MAX_LOGIN_BODY_BYTES = 8 * 1024;

  private record Check(String key, RateLimitProperties.Rule rule, boolean failClosed) {}

  private final RateLimiter rateLimiter;
  private final RateLimitProperties properties;
  private final ObjectMapper objectMapper;
  private final RateLimitResponses responses;

  public RateLimitFilter(
      RateLimiter rateLimiter, RateLimitProperties properties, ObjectMapper objectMapper) {
    this.rateLimiter = rateLimiter;
    this.properties = properties;
    this.objectMapper = objectMapper;
    this.responses = new RateLimitResponses(objectMapper);
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest original, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    HttpServletRequest request = original;
    List<Check> checks = List.of();

    if ("POST".equals(original.getMethod())) {
      String ip = original.getRemoteAddr();
      switch (RateLimitResponses.pathOf(original)) {
        case "/login" -> checks = loginChecks(ip, original.getParameter("username"));
        case "/auth/login" -> {
          byte[] body = original.getInputStream().readNBytes(MAX_LOGIN_BODY_BYTES + 1);
          if (body.length > MAX_LOGIN_BODY_BYTES) {
            responses.error(response, 413, "Request body too large");
            return;
          }
          request = new CachedBodyHttpServletRequest(original, body);
          checks = loginChecks(ip, emailFrom(body));
        }
        case "/auth/register" ->
            checks = List.of(new Check("register:" + ip, properties.register(), false));
        case "/oauth2/token" ->
            checks =
                List.of(
                    new Check("token:" + tokenClientKey(original, ip), properties.token(), true));
        default -> {}
      }
    }

    RateLimitDecision tightest = null;
    for (Check check : checks) {
      RateLimitDecision decision;
      try {
        decision = rateLimiter.tryAcquire(check.key(), check.rule().limit(), check.rule().window());
      } catch (RuntimeException e) {
        if (check.failClosed()) {
          log.error("Rate limiter unavailable, refusing request (fail-closed)", e);
          responses.error(response, 503, "Rate limiting is temporarily unavailable");
          return;
        }
        log.warn("Rate limiter unavailable, letting request through (fail-open)", e);
        continue;
      }
      if (!decision.allowed()) {
        responses.tooManyRequests(response, decision);
        return;
      }
      if (tightest == null || decision.remaining() < tightest.remaining()) {
        tightest = decision;
      }
    }
    if (tightest != null) {
      RateLimitResponses.setHeaders(response, tightest);
    }
    chain.doFilter(request, response);
  }

  private List<Check> loginChecks(String ip, String identifier) {
    List<Check> checks = new ArrayList<>();
    String normalized = normalize(identifier);
    // Hashed: keeps emails (PII) out of Redis keys and bounds the key length.
    if (normalized != null) {
      checks.add(new Check("login:" + ip + ":" + Sha256.hex(normalized), properties.login(), true));
    }
    // Wider per-IP fuse: rotating usernames from one address still runs into it.
    checks.add(new Check("login-ip:" + ip, properties.loginIp(), true));
    return checks;
  }

  // Keyed on client AND ip rather than client alone: with a per-client key, anyone could burn a
  // client's whole quota by sending its (public) client_id with a wrong secret.
  private String tokenClientKey(HttpServletRequest request, String ip) {
    String clientId = clientIdFromBasicHeader(request.getHeader("Authorization"));
    if (clientId == null) {
      clientId = request.getParameter("client_id");
    }
    return normalize(clientId) == null ? "anonymous:" + ip : Sha256.hex(clientId) + ":" + ip;
  }

  private static String clientIdFromBasicHeader(String header) {
    if (header == null || !header.regionMatches(true, 0, "Basic ", 0, 6)) {
      return null;
    }
    try {
      String decoded =
          new String(
              Base64.getDecoder().decode(header.substring(6).trim()), StandardCharsets.UTF_8);
      int colon = decoded.indexOf(':');
      return colon >= 0 ? decoded.substring(0, colon) : decoded;
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  private String emailFrom(byte[] body) {
    try {
      JsonNode email = objectMapper.readTree(body).path("email");
      return email.isString() ? email.stringValue() : null;
    } catch (RuntimeException e) {
      return null;
    }
  }

  private static String normalize(String value) {
    return value == null || value.isBlank() ? null : value.trim().toLowerCase(Locale.ROOT);
  }
}
