package com.sozureke.auth_server.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;

import com.sozureke.auth_server.role.RoleRepository;
import com.sozureke.auth_server.user.User;
import com.sozureke.auth_server.user.UserRepository;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class EndpointAccessGuardTest {

  private static final String PASSWORD = "Str0ng!Passw0rd#2026";

  @Autowired private MockMvc mockMvc;
  @Autowired private UserRepository userRepository;
  @Autowired private RoleRepository roleRepository;
  @Autowired private PasswordEncoder passwordEncoder;

  @Autowired
  @Qualifier("requestMappingHandlerMapping")
  private RequestMappingHandlerMapping handlerMapping;

  private User plain;

  private record Endpoint(HttpMethod method, String path) {}

  @BeforeEach
  void createPlainUser() {
    plain =
        new User(
            "guard-it-" + UUID.randomUUID() + "@example.com", passwordEncoder.encode(PASSWORD));
    plain.setEmailVerified(true);
    plain.getRoles().add(roleRepository.findByName("USER").orElseThrow());
    userRepository.save(plain);
  }

  private List<Endpoint> apiEndpoints() {
    List<Endpoint> endpoints = new ArrayList<>();
    handlerMapping
        .getHandlerMethods()
        .keySet()
        .forEach(
            info ->
                info.getPathPatternsCondition()
                    .getPatternValues()
                    .forEach(
                        pattern -> {
                          if (!pattern.startsWith("/api/")) {
                            return;
                          }
                          String path = pattern.replaceAll("\\{[^}]+}", "1");
                          for (RequestMethod method : info.getMethodsCondition().getMethods()) {
                            endpoints.add(new Endpoint(method.asHttpMethod(), path));
                          }
                        }));
    return endpoints;
  }

  private MockHttpServletRequestBuilder call(Endpoint endpoint) {
    return request(endpoint.method(), endpoint.path())
        .contentType(MediaType.APPLICATION_JSON)
        .content("{}");
  }

  @Test
  void theMappingActuallyContainsTheAdminApi() {
    assertThat(apiEndpoints())
        .extracting(Endpoint::path)
        .contains("/api/admin/users", "/api/admin/audit", "/api/admin/clients", "/api/clients");
    assertThat(apiEndpoints()).hasSizeGreaterThanOrEqualTo(14);
  }

  @Test
  void everyApiEndpoint_rejectsAnonymousCallers_with401() throws Exception {
    for (Endpoint endpoint : apiEndpoints()) {
      int status = mockMvc.perform(call(endpoint)).andReturn().getResponse().getStatus();
      assertThat(status).as(endpoint.toString()).isEqualTo(401);
    }
  }

  @Test
  void everyApiEndpoint_rejectsAPlainUser_with403_beforeTouchingTheRequestBody() throws Exception {
    for (Endpoint endpoint : apiEndpoints()) {
      int status =
          mockMvc
              .perform(call(endpoint).with(httpBasic(plain.getEmail(), PASSWORD)))
              .andReturn()
              .getResponse()
              .getStatus();
      assertThat(status).as(endpoint.toString()).isEqualTo(403);
    }
  }

  @Test
  void everyApiEndpoint_rejectsWrongPassword_with401() throws Exception {
    for (Endpoint endpoint : apiEndpoints().subList(0, 3)) {
      int status =
          mockMvc
              .perform(call(endpoint).with(httpBasic(plain.getEmail(), "wrong")))
              .andReturn()
              .getResponse()
              .getStatus();
      assertThat(status).as(endpoint.toString()).isEqualTo(401);
    }
  }
}
