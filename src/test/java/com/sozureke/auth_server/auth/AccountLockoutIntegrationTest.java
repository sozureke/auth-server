package com.sozureke.auth_server.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

import com.sozureke.auth_server.user.User;
import com.sozureke.auth_server.user.UserRepository;
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

@SpringBootTest
@AutoConfigureMockMvc
class AccountLockoutIntegrationTest {

  private static final String PASSWORD = "Str0ng!Passw0rd#2026";
  private static final String NEW_PASSWORD = "An0ther!Passw0rd#2026";

  @Autowired private MockMvc mockMvc;
  @Autowired private UserRepository userRepository;
  @Autowired private PasswordEncoder passwordEncoder;

  private String email;

  @BeforeEach
  void createUser() {
    email = "lockout-it-" + UUID.randomUUID() + "@example.com";
    User user = new User(email, passwordEncoder.encode(PASSWORD));
    user.setEmailVerified(true);
    userRepository.save(user);
  }

  private MockHttpServletRequestBuilder fromRandomIp(MockHttpServletRequestBuilder request) {
    ThreadLocalRandom random = ThreadLocalRandom.current();
    String ip = "10." + random.nextInt(256) + "." + random.nextInt(256) + ".7";
    return request.with(
        r -> {
          r.setRemoteAddr(ip);
          return r;
        });
  }

  private int login(String password) throws Exception {
    return mockMvc
        .perform(
            fromRandomIp(post("/auth/login"))
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"%s\",\"password\":\"%s\"}".formatted(email, password)))
        .andReturn()
        .getResponse()
        .getStatus();
  }

  private int changePassword(String currentPassword) throws Exception {
    return mockMvc
        .perform(
            fromRandomIp(put("/auth/password"))
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    "{\"email\":\"%s\",\"currentPassword\":\"%s\",\"newPassword\":\"%s\"}"
                        .formatted(email, currentPassword, NEW_PASSWORD)))
        .andReturn()
        .getResponse()
        .getStatus();
  }

  @Test
  void failedLoginAttempts_arePersisted_evenThoughTheRequestFails() throws Exception {
    assertThat(login("wrong-1")).isEqualTo(401);
    assertThat(login("wrong-2")).isEqualTo(401);

    assertThat(userRepository.findByEmail(email).orElseThrow().getFailedLoginAttempts())
        .isEqualTo(2);
  }

  @Test
  void fiveWrongLogins_lockTheAccount_evenForTheCorrectPassword() throws Exception {
    for (int i = 0; i < 5; i++) {
      assertThat(login("wrong-" + i)).isEqualTo(401);
    }

    assertThat(login(PASSWORD)).isEqualTo(423);
    assertThat(userRepository.findByEmail(email).orElseThrow().getLockedUntil()).isNotNull();
  }

  private int formLogin(String password) throws Exception {
    return mockMvc
            .perform(
                fromRandomIp(post("/login"))
                    .param("username", email)
                    .param("password", password)
                    .with(csrf()))
            .andReturn()
            .getResponse()
            .getHeader("Location")
            .endsWith("?error")
        ? 401
        : 302;
  }

  private int basicAuth(String password) throws Exception {
    return mockMvc
        .perform(fromRandomIp(get("/auth/me")).with(httpBasic(email, password)))
        .andReturn()
        .getResponse()
        .getStatus();
  }

  @Test
  void formLoginFailures_countTowardsTheLockout() throws Exception {
    for (int i = 0; i < 5; i++) {
      assertThat(formLogin("wrong-" + i)).isEqualTo(401);
    }

    assertThat(formLogin(PASSWORD)).isEqualTo(401);
    assertThat(login(PASSWORD)).isEqualTo(423);
  }

  @Test
  void basicAuthFailures_countTowardsTheLockout() throws Exception {
    for (int i = 0; i < 5; i++) {
      assertThat(basicAuth("wrong-" + i)).isEqualTo(401);
    }

    assertThat(basicAuth(PASSWORD)).isEqualTo(401);
    assertThat(login(PASSWORD)).isEqualTo(423);
  }

  @Test
  void successfulAuthentication_resetsTheCounter() throws Exception {
    assertThat(basicAuth("wrong")).isEqualTo(401);
    assertThat(formLogin("wrong")).isEqualTo(401);
    assertThat(userRepository.findByEmail(email).orElseThrow().getFailedLoginAttempts())
        .isEqualTo(2);

    assertThat(basicAuth(PASSWORD)).isEqualTo(200);

    assertThat(userRepository.findByEmail(email).orElseThrow().getFailedLoginAttempts()).isZero();
  }

  @Test
  void changePasswordEndpoint_cannotBeUsedToBruteForceAroundTheLockout() throws Exception {
    for (int i = 0; i < 5; i++) {
      assertThat(changePassword("wrong-" + i)).isEqualTo(401);
    }

    assertThat(changePassword(PASSWORD)).isEqualTo(423);
    assertThat(login(PASSWORD)).isEqualTo(423);
    User user = userRepository.findByEmail(email).orElseThrow();
    assertThat(passwordEncoder.matches(PASSWORD, user.getPasswordHash())).isTrue();
  }
}
