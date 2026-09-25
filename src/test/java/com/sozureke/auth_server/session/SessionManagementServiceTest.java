package com.sozureke.auth_server.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sozureke.auth_server.session.dto.SessionSummary;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.MapSession;
import org.springframework.session.Session;

@ExtendWith(MockitoExtension.class)
class SessionManagementServiceTest {

  private static final String PRINCIPAL = "alice@example.com";

  @Mock private FindByIndexNameSessionRepository<Session> sessionRepository;

  private SessionManagementService service;

  @BeforeEach
  void setUp() {
    service = new SessionManagementService(sessionRepository);
  }

  private static MapSession sessionWithId(String id) {
    MapSession session = new MapSession(id);
    session.setAttribute("ipAddress", "127.0.0.1");
    session.setAttribute("userAgent", "TestAgent/1.0");
    return session;
  }

  // --- listSessions
  // ----------------------------------------------------------------------------

  @Test
  void listSessions_marksTheMatchingIdAsCurrent_andOthersAsNotCurrent() {
    when(sessionRepository.findByPrincipalName(PRINCIPAL))
        .thenReturn(sessionMap(sessionWithId("session-a"), sessionWithId("session-b")));

    List<SessionSummary> summaries = service.listSessions(PRINCIPAL, "session-a");

    assertThat(summaries).hasSize(2);
    assertThat(summaries.stream().filter(SessionSummary::current)).hasSize(1);
  }

  @Test
  void listSessions_exposesIpAddressAndUserAgentFromSessionAttributes() {
    MapSession session = sessionWithId("session-a");
    when(sessionRepository.findByPrincipalName(PRINCIPAL)).thenReturn(sessionMap(session));

    SessionSummary summary = service.listSessions(PRINCIPAL, "session-a").get(0);

    assertThat(summary.ipAddress()).isEqualTo("127.0.0.1");
    assertThat(summary.userAgent()).isEqualTo("TestAgent/1.0");
  }

  @Test
  void listSessions_exposesCreationAndLastAccessedTimes() {
    MapSession session = sessionWithId("session-a");
    Instant now = Instant.parse("2026-01-01T00:00:00Z");
    session.setLastAccessedTime(now);
    when(sessionRepository.findByPrincipalName(PRINCIPAL)).thenReturn(sessionMap(session));

    SessionSummary summary = service.listSessions(PRINCIPAL, "session-a").get(0);

    assertThat(summary.createdAt()).isEqualTo(session.getCreationTime());
    assertThat(summary.lastAccessedAt()).isEqualTo(now);
  }

  @Test
  void listSessions_neverExposesTheRawSessionId() {
    MapSession session = sessionWithId("session-a");
    when(sessionRepository.findByPrincipalName(PRINCIPAL)).thenReturn(sessionMap(session));

    SessionSummary summary = service.listSessions(PRINCIPAL, "session-a").get(0);

    assertThat(summary.id()).isNotEqualTo("session-a");
  }

  @Test
  void listSessions_idIsADeterministicHash_soTheSameSessionAlwaysProducesTheSameId() {
    when(sessionRepository.findByPrincipalName(PRINCIPAL))
        .thenReturn(sessionMap(sessionWithId("session-a")))
        .thenReturn(sessionMap(sessionWithId("session-a")));

    String firstId = service.listSessions(PRINCIPAL, "session-a").get(0).id();
    String secondId = service.listSessions(PRINCIPAL, "session-a").get(0).id();

    assertThat(firstId).isEqualTo(secondId);
  }

  @Test
  void listSessions_differentSessionsProduceDifferentHashes() {
    when(sessionRepository.findByPrincipalName(PRINCIPAL))
        .thenReturn(sessionMap(sessionWithId("session-a"), sessionWithId("session-b")));

    List<SessionSummary> summaries = service.listSessions(PRINCIPAL, "session-a");

    assertThat(summaries.get(0).id()).isNotEqualTo(summaries.get(1).id());
  }

  @Test
  void listSessions_returnsEmpty_whenUserHasNoSessions() {
    when(sessionRepository.findByPrincipalName(PRINCIPAL)).thenReturn(Map.of());

    assertThat(service.listSessions(PRINCIPAL, "session-a")).isEmpty();
  }

  // --- revoke
  // ----------------------------------------------------------------------------------

  @Test
  void revoke_deletesTheSessionMatchingTheHash() {
    MapSession session = sessionWithId("session-a");
    when(sessionRepository.findByPrincipalName(PRINCIPAL)).thenReturn(sessionMap(session));
    String hash = service.listSessions(PRINCIPAL, "session-a").get(0).id();

    service.revoke(PRINCIPAL, hash);

    verify(sessionRepository).deleteById("session-a");
  }

  @Test
  void revoke_throwsSessionNotFoundException_whenHashMatchesNothing() {
    when(sessionRepository.findByPrincipalName(PRINCIPAL))
        .thenReturn(sessionMap(sessionWithId("session-a")));

    assertThatThrownBy(() -> service.revoke(PRINCIPAL, "not-a-real-hash"))
        .isInstanceOf(SessionNotFoundException.class);
    verify(sessionRepository, never()).deleteById(org.mockito.ArgumentMatchers.anyString());
  }

  @Test
  void revoke_cannotTargetAnotherUsersSession_evenWithItsRealHash() {
    // The hash is computed from another principal's session, scoped to a DIFFERENT
    // findByPrincipalName lookup than the one revoke() will perform for PRINCIPAL.
    String otherUsersHash =
        computeHashFor("victim-session"); // same algorithm the service uses internally
    when(sessionRepository.findByPrincipalName(PRINCIPAL))
        .thenReturn(sessionMap(sessionWithId("session-a"))); // attacker's own sessions only

    assertThatThrownBy(() -> service.revoke(PRINCIPAL, otherUsersHash))
        .isInstanceOf(SessionNotFoundException.class);
    verify(sessionRepository, never()).deleteById("victim-session");
  }

  private static String computeHashFor(String sessionId) {
    try {
      var digest = java.security.MessageDigest.getInstance("SHA-256");
      byte[] bytes = digest.digest(sessionId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      return java.util.HexFormat.of().formatHex(bytes);
    } catch (java.security.NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  // --- revokeAllExceptCurrent
  // ------------------------------------------------------------------

  @Test
  void revokeAllExceptCurrent_deletesEveryOtherSession_butKeepsTheCurrentOne() {
    when(sessionRepository.findByPrincipalName(PRINCIPAL))
        .thenReturn(
            sessionMap(
                sessionWithId("session-a"),
                sessionWithId("session-b"),
                sessionWithId("session-c")));

    service.revokeAllExceptCurrent(PRINCIPAL, "session-a");

    verify(sessionRepository).deleteById("session-b");
    verify(sessionRepository).deleteById("session-c");
    verify(sessionRepository, never()).deleteById("session-a");
  }

  @Test
  void revokeAllExceptCurrent_deletesNothing_whenCurrentIsTheOnlySession() {
    when(sessionRepository.findByPrincipalName(PRINCIPAL))
        .thenReturn(sessionMap(sessionWithId("session-a")));

    service.revokeAllExceptCurrent(PRINCIPAL, "session-a");

    verify(sessionRepository, never()).deleteById(org.mockito.ArgumentMatchers.anyString());
  }

  private static Map<String, Session> sessionMap(MapSession... sessions) {
    Map<String, Session> map = new LinkedHashMap<>();
    for (MapSession session : sessions) {
      map.put(session.getId(), session);
    }
    return map;
  }
}
