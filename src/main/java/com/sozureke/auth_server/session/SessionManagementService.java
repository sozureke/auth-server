package com.sozureke.auth_server.session;

import com.sozureke.auth_server.session.dto.SessionSummary;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.stereotype.Service;

@Service
public class SessionManagementService {

  private final FindByIndexNameSessionRepository<? extends Session> sessionRepository;

  public SessionManagementService(
      FindByIndexNameSessionRepository<? extends Session> sessionRepository) {
    this.sessionRepository = sessionRepository;
  }

  public List<SessionSummary> listSessions(String principalName, String currentSessionId) {
    return sessionRepository.findByPrincipalName(principalName).entrySet().stream()
        .map(e -> toSummary(e.getKey(), e.getValue(), currentSessionId))
        .toList();
  }

  public void revoke(String principalName, String targetHash) {
    findByHash(principalName, targetHash)
        .ifPresentOrElse(
            id -> sessionRepository.deleteById(id),
            () -> {
              throw new SessionNotFoundException();
            });
  }

  public void revokeAllExceptCurrent(String principalName, String currentSessionId) {
    sessionRepository.findByPrincipalName(principalName).keySet().stream()
        .filter(id -> !id.equals(currentSessionId))
        .forEach(sessionRepository::deleteById);
  }

  private Optional<String> findByHash(String principalName, String targetHash) {
    return sessionRepository.findByPrincipalName(principalName).keySet().stream()
        .filter(id -> hash(id).equals(targetHash))
        .findFirst();
  }

  private SessionSummary toSummary(String id, Session session, String currentSessionId) {
    return new SessionSummary(
        hash(id),
        id.equals(currentSessionId),
        session.getAttribute("ipAddress"),
        session.getAttribute("userAgent"),
        session.getCreationTime(),
        session.getLastAccessedTime());
  }

  private static String hash(String sessionId) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] bytes = digest.digest(sessionId.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(bytes);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}
