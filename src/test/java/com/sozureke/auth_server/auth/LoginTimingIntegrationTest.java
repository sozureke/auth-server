package com.sozureke.auth_server.auth;

import static org.assertj.core.api.Assertions.assertThat;
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
class LoginTimingIntegrationTest {

  private static final int SAMPLES = 3;

  @Autowired private MockMvc mockMvc;
  @Autowired private UserRepository userRepository;
  @Autowired private PasswordEncoder passwordEncoder;

  private String existingEmail;

  @BeforeEach
  void createUser() {
    existingEmail = "timing-it-" + UUID.randomUUID() + "@example.com";
    User user = new User(existingEmail, passwordEncoder.encode("Str0ng!Passw0rd#2026"));
    user.setEmailVerified(true);
    userRepository.save(user);
  }

  private static MockHttpServletRequestBuilder fromRandomIp(MockHttpServletRequestBuilder request) {
    ThreadLocalRandom random = ThreadLocalRandom.current();
    String ip = "10." + random.nextInt(256) + "." + random.nextInt(256) + ".11";
    return request.with(
        r -> {
          r.setRemoteAddr(ip);
          return r;
        });
  }

  private long fastestLogin(String email) throws Exception {
    long fastest = Long.MAX_VALUE;
    for (int i = 0; i < SAMPLES; i++) {
      long start = System.nanoTime();
      int status =
          mockMvc
              .perform(
                  fromRandomIp(post("/auth/login"))
                      .contentType(MediaType.APPLICATION_JSON)
                      .content("{\"email\":\"%s\",\"password\":\"wrong-%d\"}".formatted(email, i)))
              .andReturn()
              .getResponse()
              .getStatus();
      fastest = Math.min(fastest, System.nanoTime() - start);
      assertThat(status).isEqualTo(401);
    }
    return fastest;
  }

  private long fastestPasswordChange(String email) throws Exception {
    long fastest = Long.MAX_VALUE;
    for (int i = 0; i < SAMPLES; i++) {
      long start = System.nanoTime();
      int status =
          mockMvc
              .perform(
                  fromRandomIp(put("/auth/password"))
                      .contentType(MediaType.APPLICATION_JSON)
                      .content(
                          "{\"email\":\"%s\",\"currentPassword\":\"wrong-%d\",\"newPassword\":\"An0ther!Passw0rd#2026\"}"
                              .formatted(email, i)))
              .andReturn()
              .getResponse()
              .getStatus();
      fastest = Math.min(fastest, System.nanoTime() - start);
      assertThat(status).isEqualTo(401);
    }
    return fastest;
  }

  @Test
  void login_forAnUnknownEmail_takesAsLongAsAWrongPasswordForAnExistingOne() throws Exception {
    long unknown = fastestLogin("timing-ghost-" + UUID.randomUUID() + "@example.com");
    long existing = fastestLogin(existingEmail);

    assertThat(unknown).isGreaterThan(existing / 2);
  }

  @Test
  void passwordChange_forAnUnknownEmail_takesAsLongAsAWrongPasswordForAnExistingOne()
      throws Exception {
    long unknown = fastestPasswordChange("timing-ghost-" + UUID.randomUUID() + "@example.com");
    long existing = fastestPasswordChange(existingEmail);

    assertThat(unknown).isGreaterThan(existing / 2);
  }
}
