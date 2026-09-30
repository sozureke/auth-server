package com.sozureke.auth_server.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.sozureke.auth_server.role.RoleRepository;
import com.sozureke.auth_server.user.User;
import com.sozureke.auth_server.user.UserRepository;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

/** Per-principal API limit, on the real Basic-Auth chain with real users and real Redis. */
@SpringBootTest(properties = {"app.rate-limit.api.limit=2", "app.rate-limit.api.window=2s"})
@AutoConfigureMockMvc
@Transactional
class ApiRateLimitFilterTest {

  private static final String PASSWORD = "Str0ng!Passw0rd#2026";
  private static final String AUDIT = "/api/admin/audit";

  @Autowired private MockMvc mockMvc;
  @Autowired private UserRepository userRepository;
  @Autowired private RoleRepository roleRepository;
  @Autowired private PasswordEncoder passwordEncoder;
  @Autowired private StringRedisTemplate redisTemplate;

  private String emailA;
  private String emailB;

  @BeforeEach
  void createAuditors() {
    // Unique per run: a bucket left in Redis by an earlier run must not leak into this one.
    emailA = "api-rl-a-" + UUID.randomUUID() + "@example.com";
    emailB = "api-rl-b-" + UUID.randomUUID() + "@example.com";
    for (String email : new String[] {emailA, emailB}) {
      User user = new User(email, passwordEncoder.encode(PASSWORD));
      user.setEmailVerified(true);
      user.setEnabled(true);
      user.getRoles().add(roleRepository.findByName("AUDITOR").orElseThrow());
      userRepository.save(user);
    }
  }

  private int statusFor(String email) throws Exception {
    return mockMvc
        .perform(get(AUDIT).with(httpBasic(email, PASSWORD)))
        .andReturn()
        .getResponse()
        .getStatus();
  }

  @Test
  void limitsAuthenticatedUser_with429() throws Exception {
    assertThat(statusFor(emailA)).isEqualTo(200);
    assertThat(statusFor(emailA)).isEqualTo(200);

    mockMvc
        .perform(get(AUDIT).with(httpBasic(emailA, PASSWORD)))
        .andExpect(status().isTooManyRequests())
        .andExpect(header().exists("Retry-After"))
        .andExpect(jsonPath("$.status").value(429));
  }

  @Test
  void successfulResponsesCarryHeaders() throws Exception {
    mockMvc
        .perform(get(AUDIT).with(httpBasic(emailA, PASSWORD)))
        .andExpect(status().isOk())
        .andExpect(header().string("X-RateLimit-Limit", "2"))
        .andExpect(header().string("X-RateLimit-Remaining", "1"));
  }

  @Test
  void usersHaveSeparateBuckets() throws Exception {
    statusFor(emailA);
    statusFor(emailA);
    assertThat(statusFor(emailA)).isEqualTo(429);

    assertThat(statusFor(emailB)).isEqualTo(200);
  }

  // The reason the key comes from the authenticated principal and not the Authorization header:
  // wrong-password attempts using emailA's name must not eat emailA's quota.
  @Test
  void wrongPasswordAttempts_doNotConsumeTheVictimsQuota() throws Exception {
    for (int i = 0; i < 4; i++) {
      mockMvc
          .perform(get(AUDIT).with(httpBasic(emailA, "not-the-password")))
          .andExpect(status().isUnauthorized());
    }

    assertThat(statusFor(emailA)).isEqualTo(200);
  }

  @Test
  void limitResetsAfterTheWindow() throws Exception {
    statusFor(emailA);
    statusFor(emailA);
    assertThat(statusFor(emailA)).isEqualTo(429);

    Thread.sleep(2300);

    assertThat(statusFor(emailA)).isEqualTo(200);
  }

  @Test
  void unauthenticatedRequests_areRejectedWith401_andNotCounted() throws Exception {
    mockMvc
        .perform(get(AUDIT))
        .andExpect(status().isUnauthorized())
        .andExpect(header().doesNotExist("X-RateLimit-Limit"));
  }
}
