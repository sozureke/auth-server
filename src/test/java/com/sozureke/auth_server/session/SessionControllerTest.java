package com.sozureke.auth_server.session;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.sozureke.auth_server.auth.AuthUserDetails;
import com.sozureke.auth_server.config.GlobalExceptionHandler;
import com.sozureke.auth_server.session.dto.SessionSummary;
import com.sozureke.auth_server.user.User;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@ExtendWith(MockitoExtension.class)
class SessionControllerTest {

  @Mock private SessionManagementService sessionManagementService;

  private MockMvc mockMvc;
  private User user;

  @BeforeEach
  void setUp() {
    user = new User("alice@example.com", "hash");
    user.setId(1L);
    SecurityContextHolder.getContext()
        .setAuthentication(
            new UsernamePasswordAuthenticationToken(new AuthUserDetails(user), null, List.of()));

    mockMvc =
        MockMvcBuilders.standaloneSetup(new SessionController(sessionManagementService))
            .setControllerAdvice(new GlobalExceptionHandler())
            .setCustomArgumentResolvers(new AuthenticationPrincipalArgumentResolver())
            .build();
  }

  @AfterEach
  void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void list_returnsSessionsFromTheService() throws Exception {
    SessionSummary summary =
        new SessionSummary(
            "abc123", true, "127.0.0.1", "TestAgent/1.0", Instant.now(), Instant.now());
    when(sessionManagementService.listSessions(eq("alice@example.com"), anyString()))
        .thenReturn(List.of(summary));

    mockMvc
        .perform(get("/auth/sessions"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].id").value("abc123"))
        .andExpect(jsonPath("$[0].current").value(true))
        .andExpect(jsonPath("$[0].ipAddress").value("127.0.0.1"));
  }

  @Test
  void list_returnsEmptyArray_whenNoSessions() throws Exception {
    when(sessionManagementService.listSessions(eq("alice@example.com"), anyString()))
        .thenReturn(List.of());

    mockMvc
        .perform(get("/auth/sessions"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$").isEmpty());
  }

  @Test
  void revoke_returnsNoContent_onSuccess() throws Exception {
    mockMvc.perform(delete("/auth/sessions/{hash}", "abc123")).andExpect(status().isNoContent());

    verify(sessionManagementService).revoke("alice@example.com", "abc123");
  }

  @Test
  void revoke_returnsNotFound_whenHashDoesNotMatchAnOwnedSession() throws Exception {
    doThrow(new SessionNotFoundException())
        .when(sessionManagementService)
        .revoke("alice@example.com", "bogus-hash");

    mockMvc
        .perform(delete("/auth/sessions/{hash}", "bogus-hash"))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.message").value("Session not found"));
  }

  @Test
  void revokeAllExceptCurrent_returnsNoContent() throws Exception {
    mockMvc.perform(delete("/auth/sessions")).andExpect(status().isNoContent());

    verify(sessionManagementService).revokeAllExceptCurrent(eq("alice@example.com"), anyString());
  }

  @Test
  void revokeAllExceptCurrent_doesNotCallRevokeByHash() throws Exception {
    mockMvc.perform(delete("/auth/sessions")).andExpect(status().isNoContent());

    verify(sessionManagementService, never()).revoke(anyString(), anyString());
  }
}
