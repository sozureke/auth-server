package com.sozureke.auth_server.session;

import com.sozureke.auth_server.session.dto.SessionSummary;
import com.sozureke.auth_server.util.Sha256;
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
        .filter(id -> Sha256.hex(id).equals(targetHash))
        .findFirst();
  }

  private SessionSummary toSummary(String id, Session session, String currentSessionId) {
    return new SessionSummary(
        Sha256.hex(id),
        id.equals(currentSessionId),
        session.getAttribute("ipAddress"),
        session.getAttribute("userAgent"),
        session.getCreationTime(),
        session.getLastAccessedTime());
  }
}
