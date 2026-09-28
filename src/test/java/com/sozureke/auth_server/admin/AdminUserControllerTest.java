package com.sozureke.auth_server.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.sozureke.auth_server.audit.AuditEventType;
import com.sozureke.auth_server.audit.AuditService;
import com.sozureke.auth_server.mfa.BackupCode;
import com.sozureke.auth_server.mfa.BackupCodeRepository;
import com.sozureke.auth_server.role.PermissionRepository;
import com.sozureke.auth_server.role.Role;
import com.sozureke.auth_server.role.RoleRepository;
import com.sozureke.auth_server.session.SessionManagementService;
import com.sozureke.auth_server.user.User;
import com.sozureke.auth_server.user.UserRepository;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AdminUserControllerTest {

  private static final String PASSWORD = "Str0ng!Passw0rd#2026";
  private static final String BASE = "/api/admin/users";

  @Autowired private MockMvc mockMvc;
  @Autowired private UserRepository userRepository;
  @Autowired private RoleRepository roleRepository;
  @Autowired private PermissionRepository permissionRepository;
  @Autowired private BackupCodeRepository backupCodeRepository;
  @Autowired private PasswordEncoder passwordEncoder;

  @MockitoBean private AuditService auditService;
  @MockitoBean private SessionManagementService sessionManagementService;

  private final String tag = UUID.randomUUID().toString().substring(0, 8);
  private User admin;
  private User reader;
  private User plain;
  private User target;

  @BeforeEach
  void setUp() {
    admin = user("admin", roleRepository.findByName("ADMIN").orElseThrow());
    plain = user("plain", roleRepository.findByName("USER").orElseThrow());
    target = user("target", roleRepository.findByName("USER").orElseThrow());

    Role readOnly = new Role("TEST_READER_" + tag);
    readOnly.getPermissions().add(permissionRepository.findByName("USER_READ").orElseThrow());
    roleRepository.save(readOnly);
    reader = user("reader", readOnly);
  }

  private User user(String label, Role role) {
    User u =
        new User(
            "admin-it-" + label + "-" + tag + "@example.com", passwordEncoder.encode(PASSWORD));
    u.setEmailVerified(true);
    u.getRoles().add(role);
    return userRepository.save(u);
  }

  private MockHttpServletRequestBuilder as(MockHttpServletRequestBuilder request, User u) {
    return request.with(httpBasic(u.getEmail(), PASSWORD));
  }

  @Test
  void everyEndpoint_returns401_withoutCredentials() throws Exception {
    mockMvc.perform(get(BASE)).andExpect(status().isUnauthorized());
    mockMvc.perform(get(BASE + "/1")).andExpect(status().isUnauthorized());
    mockMvc.perform(put(BASE + "/1/disable")).andExpect(status().isUnauthorized());
    mockMvc.perform(delete(BASE + "/1")).andExpect(status().isUnauthorized());
    mockMvc.perform(post(BASE + "/1/force-logout")).andExpect(status().isUnauthorized());
  }

  @Test
  void everyEndpoint_returns403_forPlainUser() throws Exception {
    Long id = target.getId();
    mockMvc.perform(as(get(BASE), plain)).andExpect(status().isForbidden());
    mockMvc.perform(as(get(BASE + "/" + id), plain)).andExpect(status().isForbidden());
    mockMvc.perform(as(put(BASE + "/" + id + "/disable"), plain)).andExpect(status().isForbidden());
    mockMvc.perform(as(delete(BASE + "/" + id), plain)).andExpect(status().isForbidden());
    mockMvc
        .perform(as(post(BASE + "/" + id + "/force-logout"), plain))
        .andExpect(status().isForbidden());

    assertThat(userRepository.findById(id)).isPresent();
    assertThat(userRepository.findById(id).orElseThrow().isEnabled()).isTrue();
  }

  @Test
  void readOnlyAuthority_canRead_butNotWrite() throws Exception {
    Long id = target.getId();
    mockMvc.perform(as(get(BASE + "/" + id), reader)).andExpect(status().isOk());
    mockMvc
        .perform(as(put(BASE + "/" + id + "/disable"), reader))
        .andExpect(status().isForbidden());
    mockMvc.perform(as(delete(BASE + "/" + id), reader)).andExpect(status().isForbidden());
    mockMvc
        .perform(as(post(BASE + "/" + id + "/force-logout"), reader))
        .andExpect(status().isForbidden());
  }

  @Test
  void list_searchesByEmailFragment_caseInsensitively() throws Exception {
    mockMvc
        .perform(as(get(BASE).param("query", "ADMIN-IT-TARGET-" + tag.toUpperCase()), admin))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.content", hasSize(1)))
        .andExpect(jsonPath("$.content[0].email").value(target.getEmail()));
  }

  @Test
  void list_treatsLikeWildcardsLiterally() throws Exception {
    mockMvc
        .perform(as(get(BASE).param("query", "%"), admin))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.totalElements").value(0));
    mockMvc
        .perform(as(get(BASE).param("query", "admin_it"), admin))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.totalElements").value(0));
  }

  @Test
  void list_paginates() throws Exception {
    mockMvc
        .perform(
            as(get(BASE).param("query", "admin-it-").param("size", "2").param("page", "0"), admin))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.content", hasSize(2)))
        .andExpect(jsonPath("$.totalElements").value(4))
        .andExpect(jsonPath("$.totalPages").value(2));
  }

  @Test
  void list_rejectsSortingBySecretColumns() throws Exception {
    mockMvc
        .perform(as(get(BASE).param("sort", "passwordHash"), admin))
        .andExpect(status().isBadRequest());
    mockMvc
        .perform(as(get(BASE).param("sort", "totpSecret,desc"), admin))
        .andExpect(status().isBadRequest());
  }

  @Test
  void list_neverExposesSecrets() throws Exception {
    String body =
        mockMvc
            .perform(as(get(BASE).param("query", tag), admin))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString();

    assertThat(body)
        .doesNotContain(
            "passwordHash",
            "password_hash",
            "totpSecret",
            "resetToken",
            "verificationToken",
            "$2a$");
  }

  @Test
  void get_returnsUser_withRoles() throws Exception {
    mockMvc
        .perform(as(get(BASE + "/" + admin.getId()), admin))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.email").value(admin.getEmail()))
        .andExpect(jsonPath("$.enabled").value(true))
        .andExpect(jsonPath("$.roles[0]").value("ADMIN"));
  }

  @Test
  void get_returns404_forUnknownId() throws Exception {
    mockMvc.perform(as(get(BASE + "/999999999"), admin)).andExpect(status().isNotFound());
  }

  @Test
  void disable_disablesUser_revokesSessions_andAudits() throws Exception {
    mockMvc
        .perform(as(put(BASE + "/" + target.getId() + "/disable"), admin))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.enabled").value(false));

    assertThat(userRepository.findById(target.getId()).orElseThrow().isEnabled()).isFalse();
    verify(sessionManagementService).revokeAll(target.getEmail());
    verify(auditService)
        .log(
            eq(admin.getId()),
            eq(AuditEventType.USER_DISABLED),
            eq("user"),
            eq(target.getId().toString()),
            any());
  }

  @Test
  void disable_rejectsSelf_with409_andChangesNothing() throws Exception {
    mockMvc
        .perform(as(put(BASE + "/" + admin.getId() + "/disable"), admin))
        .andExpect(status().isConflict());

    assertThat(userRepository.findById(admin.getId()).orElseThrow().isEnabled()).isTrue();
    verify(sessionManagementService, never()).revokeAll(any());
  }

  @Test
  void disable_returns404_forUnknownId() throws Exception {
    mockMvc.perform(as(put(BASE + "/999999999/disable"), admin)).andExpect(status().isNotFound());
  }

  @Test
  void delete_removesUser_backupCodes_andSessions() throws Exception {
    Long id = target.getId();
    backupCodeRepository.save(new BackupCode(id, "hash-1"));
    backupCodeRepository.save(new BackupCode(id, "hash-2"));

    mockMvc.perform(as(delete(BASE + "/" + id), admin)).andExpect(status().isNoContent());

    userRepository.flush();
    assertThat(userRepository.findById(id)).isEmpty();
    assertThat(backupCodeRepository.findByUserIdAndUsedFalse(id)).isEmpty();
    verify(sessionManagementService).revokeAll(target.getEmail());
    verify(auditService)
        .log(
            eq(admin.getId()),
            eq(AuditEventType.USER_DELETED),
            eq("user"),
            eq(id.toString()),
            any());
  }

  @Test
  void delete_rejectsSelf_with409() throws Exception {
    mockMvc.perform(as(delete(BASE + "/" + admin.getId()), admin)).andExpect(status().isConflict());

    assertThat(userRepository.findById(admin.getId())).isPresent();
  }

  @Test
  void delete_returns404_forUnknownId() throws Exception {
    mockMvc.perform(as(delete(BASE + "/999999999"), admin)).andExpect(status().isNotFound());
  }

  @Test
  void forceLogout_revokesAllSessions_reportsCount_andAudits() throws Exception {
    when(sessionManagementService.revokeAll(target.getEmail())).thenReturn(3);

    mockMvc
        .perform(as(post(BASE + "/" + target.getId() + "/force-logout"), admin))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.sessionsRevoked", is(3)));

    verify(auditService)
        .log(
            eq(admin.getId()),
            eq(AuditEventType.USER_FORCE_LOGOUT),
            eq("user"),
            eq(target.getId().toString()),
            eq(Map.of("sessionsRevoked", 3)));
    assertThat(userRepository.findById(target.getId()).orElseThrow().isEnabled()).isTrue();
  }

  @Test
  void forceLogout_returns404_forUnknownId() throws Exception {
    mockMvc
        .perform(as(post(BASE + "/999999999/force-logout"), admin))
        .andExpect(status().isNotFound());
    verify(auditService, never()).log(anyLong(), any(), any(), any(), any());
  }
}
