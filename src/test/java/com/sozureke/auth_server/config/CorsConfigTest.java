package com.sozureke.auth_server.config;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = "app.cors.allowed-origins=https://app.example.com")
@AutoConfigureMockMvc
class CorsConfigTest {

  private static final String ALLOWED = "https://app.example.com";
  private static final String OTHER = "https://evil.example.com";

  @Autowired private MockMvc mockMvc;

  @Test
  void actualRequest_fromAllowedOrigin_getsAllowOriginAndExposedHeaders() throws Exception {
    mockMvc
        .perform(get("/auth/verify").param("token", "nope").header(HttpHeaders.ORIGIN, ALLOWED))
        .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, ALLOWED))
        .andExpect(
            header()
                .string(
                    HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS,
                    org.hamcrest.Matchers.containsString("X-RateLimit-Remaining")));
  }

  @Test
  void actualRequest_fromOtherOrigin_isRejected_withoutAllowOrigin() throws Exception {
    mockMvc
        .perform(get("/auth/verify").param("token", "nope").header(HttpHeaders.ORIGIN, OTHER))
        .andExpect(status().isForbidden())
        .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
  }

  @Test
  void preflight_onApiChain_isAnsweredBeforeAuthentication() throws Exception {
    mockMvc
        .perform(
            options("/api/admin/users")
                .header(HttpHeaders.ORIGIN, ALLOWED)
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "Authorization"))
        .andExpect(status().isOk())
        .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, ALLOWED))
        .andExpect(
            header()
                .string(
                    HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS,
                    org.hamcrest.Matchers.containsString("Authorization")))
        .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_MAX_AGE, "3600"));
  }

  @Test
  void preflight_onAuthorizationServerChain_isAnswered() throws Exception {
    mockMvc
        .perform(
            options("/oauth2/token")
                .header(HttpHeaders.ORIGIN, ALLOWED)
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "Content-Type"))
        .andExpect(status().isOk())
        .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, ALLOWED));
  }

  @Test
  void preflight_fromOtherOrigin_isRejected() throws Exception {
    mockMvc
        .perform(
            options("/api/admin/users")
                .header(HttpHeaders.ORIGIN, OTHER)
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET"))
        .andExpect(status().isForbidden())
        .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
  }

  @Test
  void preflight_forDisallowedMethod_isRejected() throws Exception {
    mockMvc
        .perform(
            options("/api/admin/users")
                .header(HttpHeaders.ORIGIN, ALLOWED)
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "PATCH"))
        .andExpect(status().isForbidden());
  }

  @Test
  void credentialsAreNotAllowedByDefault() throws Exception {
    mockMvc
        .perform(get("/auth/verify").param("token", "nope").header(HttpHeaders.ORIGIN, ALLOWED))
        .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS));
  }
}
