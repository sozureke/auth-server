package com.sozureke.auth_server.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
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
}
