package com.sozureke.auth_server.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.sozureke.auth_server.audit.AuditEventType;
import com.sozureke.auth_server.audit.AuditService;
import com.sozureke.auth_server.oauth.OAuthClient;
import com.sozureke.auth_server.oauth.OAuthClientRepository;
import com.sozureke.auth_server.role.RoleRepository;
import com.sozureke.auth_server.user.User;
import com.sozureke.auth_server.user.UserRepository;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AdminClientControllerTest {

  private static final String PASSWORD = "Str0ng!Passw0rd#2026";
  private static final String BASE = "/api/admin/clients";

  @Autowired private MockMvc mockMvc;
  @Autowired private UserRepository userRepository;
  @Autowired private RoleRepository roleRepository;
  @Autowired private OAuthClientRepository clientRepository;
  @Autowired private PasswordEncoder passwordEncoder;

  @MockitoBean private AuditService auditService;

  private final String tag = UUID.randomUUID().toString().substring(0, 8);
  private User admin;
  private User plain;
  private String clientId;

  @BeforeEach
  void setUp() {
    admin = user("admin", "ADMIN");
    plain = user("plain", "USER");

    clientId = "admin-it-client-" + tag;
    OAuthClient client = new OAuthClient();
    client.setId(UUID.randomUUID().toString());
    client.setClientId(clientId);
    client.setClientSecret(passwordEncoder.encode("original-secret"));
    client.setClientName("Original");
    client.setRedirectUris(Set.of("https://app.example.com/cb"));
    client.setScopes(Set.of("openid"));
    client.setAuthorizationGrantTypes(Set.of("authorization_code"));
    client.setClientAuthenticationMethods(Set.of("client_secret_basic"));
    clientRepository.save(client);
  }

  private User user(String label, String role) {
    User u =
        new User(
            "client-it-" + label + "-" + tag + "@example.com", passwordEncoder.encode(PASSWORD));
    u.setEmailVerified(true);
    u.getRoles().add(roleRepository.findByName(role).orElseThrow());
    return userRepository.save(u);
  }

  private MockHttpServletRequestBuilder as(MockHttpServletRequestBuilder request, User u) {
    return request.with(httpBasic(u.getEmail(), PASSWORD));
  }

  private static final String UPDATE_BODY =
      """
      {"clientName":"Renamed","redirectUris":["https://new.example.com/cb"],"scopes":["openid","profile"]}
      """;

  @Test
  void everyEndpoint_returns401_withoutCredentials() throws Exception {
    mockMvc.perform(get(BASE)).andExpect(status().isUnauthorized());
    mockMvc.perform(get(BASE + "/x")).andExpect(status().isUnauthorized());
    mockMvc.perform(put(BASE + "/x")).andExpect(status().isUnauthorized());
    mockMvc.perform(delete(BASE + "/x")).andExpect(status().isUnauthorized());
    mockMvc.perform(post(BASE + "/x/rotate-secret")).andExpect(status().isUnauthorized());
  }

  @Test
  void everyEndpoint_returns403_forNonAdmin_andChangesNothing() throws Exception {
    mockMvc.perform(as(get(BASE), plain)).andExpect(status().isForbidden());
    mockMvc.perform(as(get(BASE + "/" + clientId), plain)).andExpect(status().isForbidden());
    mockMvc
        .perform(
            as(put(BASE + "/" + clientId), plain)
                .contentType(MediaType.APPLICATION_JSON)
                .content(UPDATE_BODY))
        .andExpect(status().isForbidden());
    mockMvc.perform(as(delete(BASE + "/" + clientId), plain)).andExpect(status().isForbidden());
    mockMvc
        .perform(as(post(BASE + "/" + clientId + "/rotate-secret"), plain))
        .andExpect(status().isForbidden());

    OAuthClient untouched = clientRepository.findByClientId(clientId).orElseThrow();
    assertThat(untouched.getClientName()).isEqualTo("Original");
    verify(auditService, never()).log(any(), any(), any(), any(), any());
  }

  @Test
  void list_containsClient_withoutSecret() throws Exception {
    String body =
        mockMvc
            .perform(as(get(BASE).param("size", "200"), admin))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content[*].clientId", hasItem(clientId)))
            .andReturn()
            .getResponse()
            .getContentAsString();

    assertThat(body).doesNotContain("clientSecret", "client_secret", "$2a$");
  }

  @Test
  void list_rejectsSortingBySecret() throws Exception {
    mockMvc
        .perform(as(get(BASE).param("sort", "clientSecret"), admin))
        .andExpect(status().isBadRequest());
  }

  @Test
  void get_returnsClient() throws Exception {
    mockMvc
        .perform(as(get(BASE + "/" + clientId), admin))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.clientName").value("Original"))
        .andExpect(jsonPath("$.requireProofKey").value(true));
  }

  @Test
  void get_returns404_forUnknownClient() throws Exception {
    mockMvc.perform(as(get(BASE + "/nope-" + tag), admin)).andExpect(status().isNotFound());
  }

  @Test
  void update_changesFields_andAudits() throws Exception {
    mockMvc
        .perform(
            as(put(BASE + "/" + clientId), admin)
                .contentType(MediaType.APPLICATION_JSON)
                .content(UPDATE_BODY))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.clientName").value("Renamed"));

    OAuthClient updated = clientRepository.findByClientId(clientId).orElseThrow();
    assertThat(updated.getClientName()).isEqualTo("Renamed");
    assertThat(updated.getRedirectUris()).containsExactly("https://new.example.com/cb");
    assertThat(updated.getScopes()).containsExactlyInAnyOrder("openid", "profile");
    verify(auditService)
        .log(
            eq(admin.getId()),
            eq(AuditEventType.CLIENT_UPDATED),
            eq("client"),
            eq(clientId),
            any());
  }

  @Test
  void update_rejectsEmptyRedirectUris_with400() throws Exception {
    mockMvc
        .perform(
            as(put(BASE + "/" + clientId), admin)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"clientName\":\"X\",\"redirectUris\":[],\"scopes\":[\"openid\"]}"))
        .andExpect(status().isBadRequest());

    assertThat(clientRepository.findByClientId(clientId).orElseThrow().getClientName())
        .isEqualTo("Original");
  }

  @Test
  void update_returns404_forUnknownClient() throws Exception {
    mockMvc
        .perform(
            as(put(BASE + "/nope-" + tag), admin)
                .contentType(MediaType.APPLICATION_JSON)
                .content(UPDATE_BODY))
        .andExpect(status().isNotFound());
  }

  @Test
  void delete_removesClient_andAudits() throws Exception {
    mockMvc.perform(as(delete(BASE + "/" + clientId), admin)).andExpect(status().isNoContent());

    clientRepository.flush();
    assertThat(clientRepository.findByClientId(clientId)).isEmpty();
    verify(auditService)
        .log(
            eq(admin.getId()),
            eq(AuditEventType.CLIENT_DELETED),
            eq("client"),
            eq(clientId),
            any());
  }

  @Test
  void delete_returns404_forUnknownClient() throws Exception {
    mockMvc.perform(as(delete(BASE + "/nope-" + tag), admin)).andExpect(status().isNotFound());
  }

  @Test
  void rotateSecret_returnsNewSecretOnce_andStoresOnlyItsHash() throws Exception {
    String oldHash = clientRepository.findByClientId(clientId).orElseThrow().getClientSecret();

    String body =
        mockMvc
            .perform(as(post(BASE + "/" + clientId + "/rotate-secret"), admin))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.clientId").value(clientId))
            .andReturn()
            .getResponse()
            .getContentAsString();
    String newSecret = body.replaceAll(".*\"clientSecret\":\"([^\"]+)\".*", "$1");

    String newHash = clientRepository.findByClientId(clientId).orElseThrow().getClientSecret();
    assertThat(newHash).isNotEqualTo(oldHash).isNotEqualTo(newSecret);
    assertThat(passwordEncoder.matches(newSecret, newHash)).isTrue();
    assertThat(passwordEncoder.matches("original-secret", newHash)).isFalse();
    verify(auditService)
        .log(
            eq(admin.getId()),
            eq(AuditEventType.CLIENT_SECRET_ROTATED),
            eq("client"),
            eq(clientId),
            any());
  }
}
