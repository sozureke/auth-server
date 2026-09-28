package com.sozureke.auth_server.audit;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * Audits TOKEN_REVOKED. RFC 7009 requires a bare 200 OK on success (even for an already-invalid or
 * unknown token) — this replaces the endpoint's private default handler, so it has to replicate
 * that response itself.
 */
public class AuditingTokenRevocationSuccessHandler implements AuthenticationSuccessHandler {

  private final AuditService auditService;

  public AuditingTokenRevocationSuccessHandler(AuditService auditService) {
    this.auditService = auditService;
  }

  @Override
  public void onAuthenticationSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
    if (authentication instanceof OAuth2TokenRevocationAuthenticationToken revocation
        && revocation.getPrincipal() instanceof Authentication clientPrincipal) {
      String clientId = clientPrincipal.getName();
      Map<String, Object> details = new HashMap<>();
      details.put("tokenHash", hash(revocation.getToken()));
      if (revocation.getTokenTypeHint() != null) {
        details.put("tokenTypeHint", revocation.getTokenTypeHint());
      }
      auditService.log(null, AuditEventType.TOKEN_REVOKED, "client", clientId, details);
    }
    response.setStatus(HttpServletResponse.SC_OK);
  }

  private static String hash(String value) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(bytes);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}
