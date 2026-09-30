package com.sozureke.auth_server.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.sozureke.auth_server.auth.AuthUserDetails;
import com.sozureke.auth_server.user.User;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

@SpringBootTest
@AutoConfigureMockMvc
class CsrfAndCookieTest {

  @Autowired private MockMvc mockMvc;

  private static RequestPostProcessor sessionUser() {
    User user = new User("csrf-it-" + UUID.randomUUID() + "@example.com", "hash");
    user.setId(1L);
    return authentication(
        new UsernamePasswordAuthenticationToken(new AuthUserDetails(user), null, List.of()));
  }

  private static RequestPostProcessor randomClientIp() {
    return request -> {
      ThreadLocalRandom random = ThreadLocalRandom.current();
      request.setRemoteAddr("10." + random.nextInt(256) + "." + random.nextInt(256) + ".9");
      return request;
    };
  }

  private static String randomUsername() {
    return "csrf-it-" + UUID.randomUUID() + "@example.com";
  }

  @Test
  void formLogin_withoutCsrfToken_isForbidden() throws Exception {
    mockMvc
        .perform(
            post("/login")
                .param("username", randomUsername())
                .param("password", "x")
                .with(randomClientIp()))
        .andExpect(status().isForbidden());
  }

  @Test
  void formLogin_withCsrfToken_passesTheCsrfFilter() throws Exception {
    mockMvc
        .perform(
            post("/login")
                .param("username", randomUsername())
                .param("password", "x")
                .with(randomClientIp())
                .with(csrf()))
        .andExpect(status().is3xxRedirection());
  }

  @Test
  void logout_withoutCsrfToken_isForbidden() throws Exception {
    mockMvc.perform(post("/logout").with(sessionUser())).andExpect(status().isForbidden());
  }

  @Test
  void sessionCookieEndpoints_withoutCsrfToken_areForbidden() throws Exception {
    mockMvc.perform(delete("/auth/sessions").with(sessionUser())).andExpect(status().isForbidden());
    mockMvc
        .perform(delete("/auth/sessions/some-hash").with(sessionUser()))
        .andExpect(status().isForbidden());
  }

  @Test
  void sessionCookieEndpoints_withCsrfToken_areAllowedThrough() throws Exception {
    mockMvc
        .perform(delete("/auth/sessions").with(sessionUser()).with(csrf()))
        .andExpect(status().isNoContent());
  }

  @Test
  void tokenEndpoint_isNotSubjectToCsrf_becauseClientsAuthenticateWithCredentials()
      throws Exception {
    mockMvc
        .perform(
            post("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .with(randomClientIp()))
        .andExpect(status().is(not(403)));
  }

  @Test
  void statelessApiChain_doesNotNeedCsrf_becauseItHasNoCookieAuthentication() throws Exception {
    mockMvc
        .perform(
            post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
                .with(randomClientIp()))
        .andExpect(status().isBadRequest());
  }

  @Test
  void sessionCookie_isHttpOnly_andSameSiteLax() throws Exception {
    List<String> cookies =
        mockMvc.perform(get("/login")).andReturn().getResponse().getHeaders(HttpHeaders.SET_COOKIE);

    String session =
        cookies.stream().filter(c -> c.startsWith("SESSION=")).findFirst().orElseThrow();
    assertThat(session).contains("HttpOnly").contains("SameSite=Lax").contains("Path=/");
  }
}
