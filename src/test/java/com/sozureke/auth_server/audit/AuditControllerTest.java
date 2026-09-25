package com.sozureke.auth_server.audit;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.sozureke.auth_server.role.Role;
import com.sozureke.auth_server.role.RoleRepository;
import com.sozureke.auth_server.user.User;
import com.sozureke.auth_server.user.UserRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuditControllerTest {

  private static final String PASSWORD = "Str0ng!Passw0rd#2026";

  @Autowired private MockMvc mockMvc;
  @Autowired private UserRepository userRepository;
  @Autowired private RoleRepository roleRepository;
  @Autowired private AuditLogRepository auditLogRepository;
  @Autowired private PasswordEncoder passwordEncoder;

  private User adminUser;
  private User auditorUser;
  private User plainUser;

  @BeforeEach
  void setUp() {
    Role admin = roleRepository.findByName("ADMIN").orElseThrow();
    Role auditor = roleRepository.findByName("AUDITOR").orElseThrow();
    Role user = roleRepository.findByName("USER").orElseThrow();

    adminUser = verifiedEnabledUser("audit-it-admin@example.com");
    adminUser.getRoles().add(admin);
    userRepository.save(adminUser);

    auditorUser = verifiedEnabledUser("audit-it-auditor@example.com");
    auditorUser.getRoles().add(auditor);
    userRepository.save(auditorUser);

    plainUser = verifiedEnabledUser("audit-it-plain@example.com");
    plainUser.getRoles().add(user);
    userRepository.save(plainUser);

    auditLogRepository.save(
        new AuditLog(
            adminUser.getId(),
            AuditEventType.LOGIN,
            "user",
            adminUser.getId().toString(),
            "127.0.0.1",
            "TestAgent",
            Map.of("note", "old-login")));
    AuditLog recent =
        new AuditLog(
            adminUser.getId(),
            AuditEventType.LOGIN_FAILED,
            "user",
            adminUser.getId().toString(),
            "127.0.0.1",
            "TestAgent",
            Map.of("reason", "wrong-password"));
    auditLogRepository.save(recent);
  }

  private User verifiedEnabledUser(String email) {
    User u = new User(email, passwordEncoder.encode(PASSWORD));
    u.setEmailVerified(true);
    u.setEnabled(true);
    return u;
  }

  @Test
  void list_returnsUnauthorized_withoutCredentials() throws Exception {
    mockMvc.perform(get("/api/admin/audit")).andExpect(status().isUnauthorized());
  }

  @Test
  void list_returnsOk_forAdmin() throws Exception {
    mockMvc
        .perform(get("/api/admin/audit").with(httpBasic(adminUser.getEmail(), PASSWORD)))
        .andExpect(status().isOk());
  }

  @Test
  void list_returnsOk_forAuditor_evenWithoutAdminRole() throws Exception {
    mockMvc
        .perform(get("/api/admin/audit").with(httpBasic(auditorUser.getEmail(), PASSWORD)))
        .andExpect(status().isOk());
  }

  @Test
  void list_returnsForbidden_forPlainUser_withoutAuditReadPermission() throws Exception {
    mockMvc
        .perform(get("/api/admin/audit").with(httpBasic(plainUser.getEmail(), PASSWORD)))
        .andExpect(status().isForbidden());
  }

  @Test
  void list_filtersByAction() throws Exception {
    mockMvc
        .perform(
            get("/api/admin/audit")
                .param("action", "LOGIN_FAILED")
                .with(httpBasic(adminUser.getEmail(), PASSWORD)))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath(
                "$.content[*].action",
                org.hamcrest.Matchers.everyItem(org.hamcrest.Matchers.is("LOGIN_FAILED"))));
  }

  @Test
  void list_filtersByUserId() throws Exception {
    mockMvc
        .perform(
            get("/api/admin/audit")
                .param("userId", adminUser.getId().toString())
                .with(httpBasic(adminUser.getEmail(), PASSWORD)))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath(
                "$.content[*].userId",
                org.hamcrest.Matchers.everyItem(
                    org.hamcrest.Matchers.is(adminUser.getId().intValue()))));
  }

  @Test
  void list_excludesEntriesOutsideDateRange() throws Exception {
    String farFuture = Instant.now().plus(1, ChronoUnit.DAYS).toString();

    mockMvc
        .perform(
            get("/api/admin/audit")
                .param("from", farFuture)
                .with(httpBasic(adminUser.getEmail(), PASSWORD)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.totalElements").value(0));
  }

  @Test
  void list_respectsPageSize() throws Exception {
    mockMvc
        .perform(
            get("/api/admin/audit")
                .param("size", "1")
                .with(httpBasic(adminUser.getEmail(), PASSWORD)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.numberOfElements").value(1))
        .andExpect(jsonPath("$.size").value(1));
  }
}
