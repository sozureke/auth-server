package com.sozureke.auth_server.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * Real filter chain + real Redis. Every test gets its own client IP so buckets never overlap, and
 * requests are chosen to fail validation (400) before touching users or the audit log.
 */
@SpringBootTest(
    properties = {
      "app.rate-limit.register.limit=2",
      "app.rate-limit.register.window=2s",
      "app.rate-limit.login.limit=2",
      "app.rate-limit.login.window=2s",
      "app.rate-limit.login-ip.limit=50",
      "app.rate-limit.login-ip.window=2s",
      "app.rate-limit.token.limit=2",
      "app.rate-limit.token.window=2s"
    })
@AutoConfigureMockMvc
class RateLimitFilterTest {

  private static final String BAD_REGISTER = "{\"email\":\"x\",\"password\":\"weak\"}";

  @Autowired private MockMvc mockMvc;
  @Autowired private StringRedisTemplate redisTemplate;

  private final String ip =
      "10."
          + ThreadLocalRandom.current().nextInt(256)
          + "."
          + ThreadLocalRandom.current().nextInt(256)
          + ".7";

  @AfterEach
  void cleanUp() {
    Set<String> keys = redisTemplate.keys("rate-limit:*" + ip + "*");
    if (keys != null && !keys.isEmpty()) {
      redisTemplate.delete(keys);
    }
  }

  private MockHttpServletRequestBuilder fromIp(MockHttpServletRequestBuilder builder) {
    return builder.with(
        request -> {
          request.setRemoteAddr(ip);
          return request;
        });
  }

  private int statusOf(MockHttpServletRequestBuilder builder) throws Exception {
    return mockMvc.perform(fromIp(builder)).andReturn().getResponse().getStatus();
  }

  private MockHttpServletRequestBuilder register() {
    return post("/auth/register").contentType(MediaType.APPLICATION_JSON).content(BAD_REGISTER);
  }

  private MockHttpServletRequestBuilder jsonLogin(String email) {
    return post("/auth/login")
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"email\":\"" + email + "\",\"password\":\"\"}");
  }

  private MockHttpServletRequestBuilder tokenRequest(String clientId) {
    String basic =
        Base64.getEncoder().encodeToString((clientId + ":secret").getBytes(StandardCharsets.UTF_8));
    return post("/oauth2/token")
        .header("Authorization", "Basic " + basic)
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .content("grant_type=authorization_code&code=x&redirect_uri=http://x");
  }

  @Test
  void register_isLimitedPerIp_with429AndRetryAfter() throws Exception {
    assertThat(statusOf(register())).isEqualTo(400);
    assertThat(statusOf(register())).isEqualTo(400);

    mockMvc
        .perform(fromIp(register()))
        .andExpect(status().isTooManyRequests())
        .andExpect(header().exists("Retry-After"))
        .andExpect(jsonPath("$.status").value(429));
  }

  @Test
  void responses_carryRateLimitHeaders_thatCountDown() throws Exception {
    mockMvc
        .perform(fromIp(register()))
        .andExpect(header().string("X-RateLimit-Limit", "2"))
        .andExpect(header().string("X-RateLimit-Remaining", "1"))
        .andExpect(header().exists("X-RateLimit-Reset"));
    mockMvc.perform(fromIp(register())).andExpect(header().string("X-RateLimit-Remaining", "0"));
  }

  @Test
  void limitResetsAfterTheWindow() throws Exception {
    statusOf(register());
    statusOf(register());
    assertThat(statusOf(register())).isEqualTo(429);

    Thread.sleep(2300);

    assertThat(statusOf(register())).isEqualTo(400);
  }

  @Test
  void differentIps_doNotShareABucket() throws Exception {
    statusOf(register());
    statusOf(register());
    assertThat(statusOf(register())).isEqualTo(429);

    int other =
        mockMvc
            .perform(
                register()
                    .with(
                        request -> {
                          request.setRemoteAddr(ip + "9");
                          return request;
                        }))
            .andReturn()
            .getResponse()
            .getStatus();
    redisTemplate.delete(redisTemplate.keys("rate-limit:*" + ip + "9*"));

    assertThat(other).isEqualTo(400);
  }

  @Test
  void jsonLogin_isLimitedPerEmail_notPerIpAlone() throws Exception {
    assertThat(statusOf(jsonLogin("victim@example.com"))).isEqualTo(400);
    assertThat(statusOf(jsonLogin("victim@example.com"))).isEqualTo(400);

    assertThat(statusOf(jsonLogin("victim@example.com"))).isEqualTo(429);
    // Same address, other account: not blocked by the first one's bucket.
    assertThat(statusOf(jsonLogin("someone-else@example.com"))).isEqualTo(400);
  }

  @Test
  void jsonLogin_emailMatchingIgnoresCase() throws Exception {
    statusOf(jsonLogin("Mixed@Example.com"));
    statusOf(jsonLogin("mixed@example.com"));

    assertThat(statusOf(jsonLogin("MIXED@EXAMPLE.COM"))).isEqualTo(429);
  }

  @Test
  void jsonLogin_bodyStillReachesTheController_afterTheFilterReadIt() throws Exception {
    // A 400 with a per-field error proves the controller could still parse the JSON body.
    mockMvc
        .perform(fromIp(jsonLogin("body-check@example.com")))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.fieldErrors.password").exists());
  }

  @Test
  void jsonLogin_rejectsOversizedBodies() throws Exception {
    String huge = "{\"email\":\"a@example.com\",\"password\":\"" + "x".repeat(9000) + "\"}";

    mockMvc
        .perform(fromIp(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content(huge)))
        .andExpect(status().isPayloadTooLarge());
  }

  @Test
  void formLogin_isLimitedPerUsername() throws Exception {
    MockHttpServletRequestBuilder attempt =
        post("/login")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .content("username=form-victim@example.com&password=x");

    assertThat(statusOf(attempt)).isNotEqualTo(429);
    assertThat(statusOf(attempt)).isNotEqualTo(429);

    assertThat(statusOf(attempt)).isEqualTo(429);
  }

  @Test
  void tokenEndpoint_isLimitedPerClient_andClientsDoNotShareABucket() throws Exception {
    assertThat(statusOf(tokenRequest("client-a"))).isNotEqualTo(429);
    assertThat(statusOf(tokenRequest("client-a"))).isNotEqualTo(429);

    assertThat(statusOf(tokenRequest("client-a"))).isEqualTo(429);
    assertThat(statusOf(tokenRequest("client-b"))).isNotEqualTo(429);
  }

  @Test
  void unlimitedPaths_areUntouched() throws Exception {
    mockMvc
        .perform(fromIp(get("/actuator/health")))
        .andExpect(status().isOk())
        .andExpect(header().doesNotExist("X-RateLimit-Limit"));
  }
}
