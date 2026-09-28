package com.sozureke.auth_server.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.sozureke.auth_server.audit.AuditEventType;
import com.sozureke.auth_server.audit.AuditLog;
import com.sozureke.auth_server.audit.AuditLogRepository;
import com.sozureke.auth_server.role.RoleRepository;
import com.sozureke.auth_server.user.User;
import com.sozureke.auth_server.user.UserRepository;
import com.sozureke.auth_server.util.Sha256;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AdminSessionsAndMetricsTest {

  private static final String PASSWORD = "Str0ng!Passw0rd#2026";

  @Autowired private MockMvc mockMvc;
  @Autowired private UserRepository userRepository;
  @Autowired private RoleRepository roleRepository;
  @Autowired private AuditLogRepository auditLogRepository;
  @Autowired private PasswordEncoder passwordEncoder;
  @Autowired private StringRedisTemplate redisTemplate;
  @Autowired private ObjectMapper objectMapper;

  @Autowired private FindByIndexNameSessionRepository<? extends Session> sessionRepository;

  private final String tag = UUID.randomUUID().toString().substring(0, 8);
  private User admin;
  private User plain;
  private String sessionId;
  private String sessionPrincipal;

  @BeforeEach
  void setUp() {
    admin = user("admin", "ADMIN");
    plain = user("plain", "USER");
    sessionPrincipal = "sessions-it-" + tag + "@example.com";
    sessionId = createSession(sessionPrincipal);
  }

  @AfterEach
  void deleteSession() {
    sessionRepository.deleteById(sessionId);
  }

  private <S extends Session> String createSession(String principal) {
    @SuppressWarnings("unchecked")
    FindByIndexNameSessionRepository<S> repository =
        (FindByIndexNameSessionRepository<S>) sessionRepository;
    S session = repository.createSession();
    session.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, principal);
    session.setAttribute("ipAddress", "203.0.113.9");
    session.setAttribute("userAgent", "SessionsIT/1.0");
    repository.save(session);
    return session.getId();
  }

  private User user(String label, String role) {
    User u =
        new User(
            "sessions-it-" + label + "-" + tag + "@example.com", passwordEncoder.encode(PASSWORD));
    u.setEmailVerified(true);
    u.getRoles().add(roleRepository.findByName(role).orElseThrow());
    return userRepository.save(u);
  }

  private MockHttpServletRequestBuilder as(MockHttpServletRequestBuilder request, User u) {
    return request.with(httpBasic(u.getEmail(), PASSWORD));
  }

  private JsonNode metrics() throws Exception {
    return objectMapper.readTree(
        mockMvc
            .perform(as(get("/api/admin/metrics"), admin))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString());
  }

  @Test
  void bothEndpoints_return401_withoutCredentials() throws Exception {
    mockMvc.perform(get("/api/admin/sessions")).andExpect(status().isUnauthorized());
    mockMvc.perform(get("/api/admin/metrics")).andExpect(status().isUnauthorized());
  }

  @Test
  void bothEndpoints_return403_forPlainUser() throws Exception {
    mockMvc.perform(as(get("/api/admin/sessions"), plain)).andExpect(status().isForbidden());
    mockMvc.perform(as(get("/api/admin/metrics"), plain)).andExpect(status().isForbidden());
  }

  @Test
  void sessions_listsRealSession_withHashedId_andMetadata() throws Exception {
    String body =
        mockMvc
            .perform(as(get("/api/admin/sessions").param("size", "500"), admin))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content[*].principal", hasItem(sessionPrincipal)))
            .andReturn()
            .getResponse()
            .getContentAsString();

    JsonNode ours = null;
    for (JsonNode s : objectMapper.readTree(body).path("content")) {
      if (sessionPrincipal.equals(s.path("principal").asString())) {
        ours = s;
      }
    }
    assertThat(ours).isNotNull();
    assertThat(ours.path("id").asString()).isEqualTo(Sha256.hex(sessionId));
    assertThat(ours.path("ipAddress").asString()).isEqualTo("203.0.113.9");
    assertThat(ours.path("userAgent").asString()).isEqualTo("SessionsIT/1.0");
    assertThat(body).doesNotContain(sessionId);
  }

  @Test
  void sessions_paginates() throws Exception {
    String second = createSession(sessionPrincipal);
    try {
      mockMvc
          .perform(as(get("/api/admin/sessions").param("size", "1").param("page", "0"), admin))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.content.length()").value(1))
          .andExpect(
              jsonPath("$.totalElements").value(org.hamcrest.Matchers.greaterThanOrEqualTo(2)));
    } finally {
      sessionRepository.deleteById(second);
    }
  }

  @Test
  void metrics_countsUsers_sessions_andRecentFailedLoginsOnly() throws Exception {
    long usersBefore = metrics().path("totalUsers").asLong();
    long sessionsBefore = metrics().path("activeSessions").asLong();
    long failedBefore = metrics().path("failedLoginsLast24h").asLong();

    userRepository.save(new User("sessions-it-extra-" + tag + "@example.com", "hash"));
    String extraSession = createSession("sessions-it-extra-" + tag + "@example.com");
    auditLogRepository.save(failedLogin(Instant.now().minus(1, ChronoUnit.HOURS)));
    auditLogRepository.save(failedLogin(Instant.now().minus(25, ChronoUnit.HOURS)));
    auditLogRepository.flush();
    try {
      JsonNode after = metrics();
      assertThat(after.path("totalUsers").asLong()).isEqualTo(usersBefore + 1);
      assertThat(after.path("activeSessions").asLong()).isEqualTo(sessionsBefore + 1);
      assertThat(after.path("failedLoginsLast24h").asLong()).isEqualTo(failedBefore + 1);
    } finally {
      sessionRepository.deleteById(extraSession);
    }
  }

  private AuditLog failedLogin(Instant at) {
    AuditLog log =
        new AuditLog(admin.getId(), AuditEventType.LOGIN_FAILED, "user", "x", null, null, Map.of());
    ReflectionTestUtils.setField(log, "createdAt", at);
    return log;
  }
}
