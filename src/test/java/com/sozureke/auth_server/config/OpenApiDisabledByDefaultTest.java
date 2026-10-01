package com.sozureke.auth_server.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("prod")
class OpenApiDisabledByDefaultTest {

  @Autowired private MockMvc mockMvc;

  @Test
  void specAndUi_areNotServed_inProd() throws Exception {
    for (String path :
        new String[] {"/v3/api-docs", "/swagger-ui/index.html", "/swagger-ui.html"}) {
      int status = mockMvc.perform(get(path)).andReturn().getResponse().getStatus();
      assertThat(status).as(path).isEqualTo(404);
    }
  }
}
