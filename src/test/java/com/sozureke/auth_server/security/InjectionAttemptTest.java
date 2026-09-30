package com.sozureke.auth_server.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.sozureke.auth_server.role.RoleRepository;
import com.sozureke.auth_server.user.User;
import com.sozureke.auth_server.user.UserRepository;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class InjectionAttemptTest {

  private static final String PASSWORD = "Str0ng!Passw0rd#2026";

  private static final List<String> PAYLOADS =
      List.of(
          "' OR '1'='1",
          "' OR 1=1 --",
          "x'; DROP TABLE users; --",
          "\" OR \"\"=\"",
          "admin'--",
          "%' OR email LIKE '%",
          "1; SELECT pg_sleep(5)");

  @Autowired private MockMvc mockMvc;
  @Autowired private UserRepository userRepository;
  @Autowired private RoleRepository roleRepository;
  @Autowired private PasswordEncoder passwordEncoder;

  private User admin;

  @BeforeEach
  void setUp() {
    admin =
        new User(
            "inject-it-" + UUID.randomUUID() + "@example.com", passwordEncoder.encode(PASSWORD));
    admin.setEmailVerified(true);
    admin.getRoles().add(roleRepository.findByName("ADMIN").orElseThrow());
    userRepository.save(admin);
  }

  private MockHttpServletRequestBuilder asAdmin(MockHttpServletRequestBuilder request) {
    return request.with(httpBasic(admin.getEmail(), PASSWORD));
  }

  private static MockHttpServletRequestBuilder fromRandomIp(MockHttpServletRequestBuilder request) {
    ThreadLocalRandom random = ThreadLocalRandom.current();
    String ip = "10." + random.nextInt(256) + "." + random.nextInt(256) + ".3";
    return request.with(
        r -> {
          r.setRemoteAddr(ip);
          return r;
        });
  }

  @Test
  void userSearch_treatsInjectionPayloadsAsPlainText() throws Exception {
    long users = userRepository.count();
    for (String payload : PAYLOADS) {
      mockMvc
          .perform(asAdmin(get("/api/admin/users").param("query", payload)))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.totalElements").value(0));
    }
    assertThat(userRepository.count()).isEqualTo(users);
  }

  @Test
  void auditFilters_rejectInjectionPayloads_asBadRequests() throws Exception {
    for (String payload : PAYLOADS) {
      mockMvc
          .perform(asAdmin(get("/api/admin/audit").param("action", payload)))
          .andExpect(status().isBadRequest());
      mockMvc
          .perform(asAdmin(get("/api/admin/audit").param("userId", payload)))
          .andExpect(status().isBadRequest());
      mockMvc
          .perform(asAdmin(get("/api/admin/audit").param("from", payload)))
          .andExpect(status().isBadRequest());
    }
  }

  @Test
  void sortParameters_cannotCarryInjections() throws Exception {
    for (String payload : PAYLOADS) {
      mockMvc
          .perform(asAdmin(get("/api/admin/users").param("sort", payload)))
          .andExpect(status().isBadRequest());
      mockMvc
          .perform(asAdmin(get("/api/admin/clients").param("sort", payload)))
          .andExpect(status().isBadRequest());
    }
  }

  @Test
  void pathVariables_withInjectionPayloads_areRejected() throws Exception {
    mockMvc
        .perform(asAdmin(get("/api/admin/users/{id}", "1 OR 1=1")))
        .andExpect(status().isBadRequest());
    mockMvc
        .perform(asAdmin(get("/api/admin/clients/{id}", "x' OR '1'='1")))
        .andExpect(status().isNotFound());
  }

  @Test
  void login_withInjectionPayloadsAsEmailOrPassword_neverAuthenticates() throws Exception {
    for (String payload : PAYLOADS) {
      int asEmail =
          mockMvc
              .perform(
                  fromRandomIp(post("/auth/login"))
                      .contentType(MediaType.APPLICATION_JSON)
                      .content(
                          "{\"email\":%s,\"password\":\"x\"}"
                              .formatted(
                                  tools.jackson.databind.json.JsonMapper.shared()
                                      .writeValueAsString(payload))))
              .andReturn()
              .getResponse()
              .getStatus();
      assertThat(asEmail).as(payload).isIn(400, 401);

      int asPassword =
          mockMvc
              .perform(
                  fromRandomIp(post("/auth/login"))
                      .contentType(MediaType.APPLICATION_JSON)
                      .content(
                          "{\"email\":\"%s\",\"password\":%s}"
                              .formatted(
                                  admin.getEmail(),
                                  tools.jackson.databind.json.JsonMapper.shared()
                                      .writeValueAsString(payload))))
              .andReturn()
              .getResponse()
              .getStatus();
      assertThat(asPassword).as(payload).isIn(401, 423);
    }
  }
}
