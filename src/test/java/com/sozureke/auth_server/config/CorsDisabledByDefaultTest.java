package com.sozureke.auth_server.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class CorsDisabledByDefaultTest {

  @Autowired private MockMvc mockMvc;

  @Test
  void withoutConfiguredOrigins_noCrossOriginAccessIsGranted() throws Exception {
    mockMvc
        .perform(
            get("/auth/verify")
                .param("token", "nope")
                .header(HttpHeaders.ORIGIN, "https://app.example.com"))
        .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
  }

  @Test
  void withoutConfiguredOrigins_preflightGetsNoAllowOrigin() throws Exception {
    mockMvc
        .perform(
            options("/api/admin/users")
                .header(HttpHeaders.ORIGIN, "https://app.example.com")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET"))
        .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
  }

  @Test
  void wildcardOriginWithCredentials_isRejectedAtConfigurationTime() {
    assertThatThrownBy(
            () -> new CorsProperties(List.of("*"), null, null, null, true, Duration.ofHours(1)))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void propertiesFallBackToSafeDefaults() {
    CorsProperties properties = new CorsProperties(null, null, null, null, false, null);

    assertThat(properties.allowedOrigins()).isEmpty();
    assertThat(properties.allowedMethods()).contains("GET", "POST").doesNotContain("PATCH");
    assertThat(properties.exposedHeaders()).contains("X-RateLimit-Remaining", "Retry-After");
    assertThat(properties.allowCredentials()).isFalse();
    assertThat(properties.maxAge()).isEqualTo(Duration.ofHours(1));
  }
}
