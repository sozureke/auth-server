package com.sozureke.auth_server.mfa;

import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.sozureke.auth_server.auth.AuthUserDetails;
import com.sozureke.auth_server.auth.exception.InvalidCredentialsException;
import com.sozureke.auth_server.config.GlobalExceptionHandler;
import com.sozureke.auth_server.user.User;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@ExtendWith(MockitoExtension.class)
class MfaControllerTest {

  private static final byte[] PNG_MAGIC = {(byte) 0x89, 'P', 'N', 'G'};

  @Mock private MfaService mfaService;

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
        MockMvcBuilders.standaloneSetup(new MfaController(mfaService))
            .setControllerAdvice(new GlobalExceptionHandler())
            .setCustomArgumentResolvers(new AuthenticationPrincipalArgumentResolver())
            .build();
  }

  @AfterEach
  void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void qr_returnsPngImage() throws Exception {
    byte[] png = new byte[] {PNG_MAGIC[0], PNG_MAGIC[1], PNG_MAGIC[2], PNG_MAGIC[3], 1, 2, 3};
    when(mfaService.pendingEnrollmentQr(user)).thenReturn(png);

    mockMvc
        .perform(get("/auth/mfa/qr"))
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.IMAGE_PNG))
        .andExpect(content().bytes(png));
  }

  @Test
  void qr_errorsStayJson_whenEnrollmentNotStarted() throws Exception {
    when(mfaService.pendingEnrollmentQr(user)).thenThrow(new MfaNotStartedException());

    mockMvc
        .perform(get("/auth/mfa/qr").accept(MediaType.ALL))
        .andExpect(status().isConflict())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath("$.status").value(409))
        .andExpect(jsonPath("$.message").isNotEmpty());
  }

  @Test
  void qr_errorsStayJson_whenMfaAlreadyEnabled() throws Exception {
    when(mfaService.pendingEnrollmentQr(user)).thenThrow(new MfaAlreadyEnabledException());

    mockMvc
        .perform(get("/auth/mfa/qr").accept(MediaType.ALL))
        .andExpect(status().isConflict())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath("$.message").value("MFA is already enabled"));
  }

  @Test
  void disable_returnsOk_whenPasswordCorrect() throws Exception {
    doNothing().when(mfaService).disable(user, "CorrectHorse1!");

    mockMvc
        .perform(
            post("/auth/mfa/disable")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"password\":\"CorrectHorse1!\"}"))
        .andExpect(status().isOk());

    verify(mfaService).disable(user, "CorrectHorse1!");
  }

  @Test
  void disable_returnsUnauthorized_whenPasswordWrong() throws Exception {
    doThrow(new InvalidCredentialsException()).when(mfaService).disable(user, "WrongPassword1!");

    mockMvc
        .perform(
            post("/auth/mfa/disable")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"password\":\"WrongPassword1!\"}"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.message").value("Invalid email or password"));
  }

  @Test
  void disable_returnsConflict_whenMfaNotEnabled() throws Exception {
    doThrow(new MfaNotStartedException()).when(mfaService).disable(user, "CorrectHorse1!");

    mockMvc
        .perform(
            post("/auth/mfa/disable")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"password\":\"CorrectHorse1!\"}"))
        .andExpect(status().isConflict());
  }

  @Test
  void disable_rejectsBlankPassword() throws Exception {
    mockMvc
        .perform(
            post("/auth/mfa/disable")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"password\":\"\"}"))
        .andExpect(status().isBadRequest());
  }
}
