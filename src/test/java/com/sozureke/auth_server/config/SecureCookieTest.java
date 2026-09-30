package com.sozureke.auth_server.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = "app.session.cookie.secure=true")
@AutoConfigureMockMvc
class SecureCookieTest {

  @Autowired private MockMvc mockMvc;

  @Test
  void sessionCookie_isSecure_whenConfigured_evenOverPlainHttp() throws Exception {
    List<String> cookies =
        mockMvc.perform(get("/login")).andReturn().getResponse().getHeaders(HttpHeaders.SET_COOKIE);

    String session =
        cookies.stream().filter(c -> c.startsWith("SESSION=")).findFirst().orElseThrow();
    assertThat(session).contains("Secure").contains("HttpOnly").contains("SameSite=Lax");
  }
}
