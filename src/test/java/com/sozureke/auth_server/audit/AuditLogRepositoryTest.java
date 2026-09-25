package com.sozureke.auth_server.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@Transactional
class AuditLogRepositoryTest {

  @Autowired private AuditLogRepository auditLogRepository;

  @Test
  void save_roundTripsJsonbDetails() {
    AuditLog log =
        new AuditLog(
            1L,
            AuditEventType.LOGIN_FAILED,
            "user",
            "1",
            "127.0.0.1",
            "TestAgent/1.0",
            Map.of("reason", "wrong-password", "attempts", 3));

    AuditLog saved = auditLogRepository.save(log);
    auditLogRepository.flush();
    AuditLog reloaded = auditLogRepository.findById(saved.getId()).orElseThrow();

    assertThat(reloaded.getDetails()).containsEntry("reason", "wrong-password");
    assertThat(reloaded.getDetails()).containsEntry("attempts", 3);
    assertThat(reloaded.getAction()).isEqualTo("LOGIN_FAILED");
    assertThat(reloaded.getCreatedAt()).isNotNull();
  }

  // --- search
  // -----------------------------------------------------------------------------------
  // Regression coverage for a real Postgres bug (not a Java one): the naive JPQL
  // "(:param IS NULL OR field = :param)" pattern fails at runtime with "could not determine
  // data type of parameter" because Postgres's extended query protocol can't infer a bind
  // parameter's type from an IS NULL check alone. Fixed with an explicit CAST on that side too
  // (see AuditLogRepository) — these tests exist to catch a regression back to the naive form,
  // which compiles fine and only breaks against a real Postgres connection.

  @BeforeEach
  void seedSearchFixtures() {
    auditLogRepository.save(
        new AuditLog(1L, AuditEventType.LOGIN, "user", "1", "127.0.0.1", "TestAgent", null));
    auditLogRepository.save(
        new AuditLog(1L, AuditEventType.LOGIN_FAILED, "user", "1", "127.0.0.1", "TestAgent", null));
    auditLogRepository.flush();
  }

  @Test
  void search_withAllFiltersNull_doesNotThrow_andReturnsResults() {
    Page<AuditLog> page = auditLogRepository.search(null, null, null, null, PageRequest.of(0, 10));

    assertThat(page.getTotalElements()).isGreaterThanOrEqualTo(2);
  }

  @Test
  void search_filtersByUserId() {
    Page<AuditLog> page = auditLogRepository.search(1L, null, null, null, PageRequest.of(0, 10));

    assertThat(page.getContent()).allMatch(a -> a.getUserId().equals(1L));
  }

  @Test
  void search_filtersByAction() {
    Page<AuditLog> page =
        auditLogRepository.search(null, "LOGIN_FAILED", null, null, PageRequest.of(0, 10));

    assertThat(page.getContent()).allMatch(a -> a.getAction().equals("LOGIN_FAILED"));
  }

  @Test
  void search_excludesEntriesBeforeFrom() {
    Instant farFuture = Instant.now().plus(1, ChronoUnit.DAYS);

    Page<AuditLog> page =
        auditLogRepository.search(null, null, farFuture, null, PageRequest.of(0, 10));

    assertThat(page.getContent()).isEmpty();
  }

  @Test
  void search_excludesEntriesAfterTo() {
    Instant farPast = Instant.now().minus(1, ChronoUnit.DAYS);

    Page<AuditLog> page =
        auditLogRepository.search(null, null, null, farPast, PageRequest.of(0, 10));

    assertThat(page.getContent()).isEmpty();
  }

  @Test
  void search_respectsPageSize() {
    Page<AuditLog> page = auditLogRepository.search(null, null, null, null, PageRequest.of(0, 1));

    assertThat(page.getContent()).hasSize(1);
    assertThat(page.getTotalElements()).isGreaterThanOrEqualTo(2);
  }
}
