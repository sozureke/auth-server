package com.sozureke.auth_server.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class OpenApiDocsTest {

  @Autowired private MockMvc mockMvc;
  @Autowired private ObjectMapper objectMapper;

  private JsonNode spec() throws Exception {
    return objectMapper.readTree(
        mockMvc
            .perform(get("/v3/api-docs"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString());
  }

  private static List<Map.Entry<String, JsonNode>> operations(JsonNode spec) {
    List<Map.Entry<String, JsonNode>> operations = new ArrayList<>();
    for (Map.Entry<String, JsonNode> path : spec.path("paths").properties()) {
      for (Map.Entry<String, JsonNode> operation : path.getValue().properties()) {
        operations.add(Map.entry(operation.getKey() + " " + path.getKey(), operation.getValue()));
      }
    }
    return operations;
  }

  @Test
  void specIsPublishedAnonymously_inDev_andCoversTheApi() throws Exception {
    JsonNode spec = spec();

    assertThat(spec.path("info").path("title").asString()).isEqualTo("auth-server API");
    assertThat(spec.path("paths").propertyNames())
        .contains(
            "/auth/register",
            "/auth/login",
            "/auth/mfa/enable",
            "/auth/sessions",
            "/api/admin/users",
            "/api/admin/users/{id}/force-logout",
            "/api/admin/clients/{clientId}/rotate-secret",
            "/api/admin/audit",
            "/api/admin/metrics",
            "/api/clients")
        .noneMatch(path -> path.startsWith("/login") || path.startsWith("/oauth2"));
    assertThat(operations(spec)).hasSizeGreaterThanOrEqualTo(28);
  }

  @Test
  void everyOperation_hasASummaryAndATag() throws Exception {
    for (Map.Entry<String, JsonNode> operation : operations(spec())) {
      assertThat(operation.getValue().path("summary").asString())
          .as(operation.getKey())
          .isNotBlank();
      assertThat(operation.getValue().path("tags").isEmpty()).as(operation.getKey()).isFalse();
    }
  }

  @Test
  void securitySchemes_matchHowEachEndpointIsReallyAuthenticated() throws Exception {
    JsonNode spec = spec();

    assertThat(spec.path("components").path("securitySchemes").propertyNames())
        .containsExactlyInAnyOrder("basicAuth", "sessionCookie");
    assertThat(spec.at("/paths/~1auth~1register/post/security").isArray()).isTrue();
    assertThat(spec.at("/paths/~1auth~1register/post/security").isEmpty()).isTrue();
    assertThat(spec.at("/paths/~1auth~1sessions/get/security/0").propertyNames())
        .containsExactly("sessionCookie");
    assertThat(spec.at("/paths/~1api~1admin~1users/get/security").isMissingNode()).isTrue();
    assertThat(spec.at("/security/0").propertyNames()).containsExactly("basicAuth");
  }

  @Test
  void pageableIsExposedAsQueryParameters_andPrincipalIsHidden() throws Exception {
    JsonNode parameters = spec().at("/paths/~1api~1admin~1users/get/parameters");
    List<String> names = new ArrayList<>();
    parameters.forEach(parameter -> names.add(parameter.path("name").asString()));

    assertThat(names).contains("query", "page", "size", "sort").doesNotContain("pageable");

    JsonNode disable = spec().at("/paths/~1api~1admin~1users~1{id}~1disable/put/parameters");
    List<String> disableNames = new ArrayList<>();
    disable.forEach(parameter -> disableNames.add(parameter.path("name").asString()));
    assertThat(disableNames).containsExactly("id");
  }

  @Test
  void swaggerUi_isServed_inDev() throws Exception {
    mockMvc.perform(get("/swagger-ui/index.html")).andExpect(status().isOk());
  }
}
