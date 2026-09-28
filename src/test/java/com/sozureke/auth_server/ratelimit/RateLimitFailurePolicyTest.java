package com.sozureke.auth_server.ratelimit;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Redis outage policy: brute-force-facing endpoints fail closed, registration fails open. Pinned in
 * a test because the two directions are a deliberate trade-off (see TODO.md 7.2), not an accident.
 */
@SpringBootTest
@AutoConfigureMockMvc
class RateLimitFailurePolicyTest {

  @Autowired private MockMvc mockMvc;
  @MockitoBean private RateLimiter rateLimiter;

  @BeforeEach
  void redisIsDown() {
    when(rateLimiter.tryAcquire(anyString(), anyInt(), any()))
        .thenThrow(new RedisConnectionFailureException("redis is down"));
  }

  @Test
  void register_failsOpen_requestStillReachesTheController() throws Exception {
    mockMvc
        .perform(
            post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"x\",\"password\":\"weak\"}"))
        .andExpect(status().isBadRequest());
  }

  @Test
  void jsonLogin_failsClosed() throws Exception {
    mockMvc
        .perform(
            post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"a@example.com\",\"password\":\"x\"}"))
        .andExpect(status().isServiceUnavailable())
        .andExpect(jsonPath("$.status").value(503));
  }

  @Test
  void formLogin_failsClosed() throws Exception {
    mockMvc
        .perform(
            post("/login")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .content("username=a@example.com&password=x"))
        .andExpect(status().isServiceUnavailable());
  }

  @Test
  void tokenEndpoint_failsClosed() throws Exception {
    mockMvc
        .perform(
            post("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .content("grant_type=authorization_code"))
        .andExpect(status().isServiceUnavailable());
  }
}
