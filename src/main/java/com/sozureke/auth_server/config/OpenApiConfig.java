package com.sozureke.auth_server.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

  public static final String BASIC_AUTH = "basicAuth";
  public static final String SESSION_COOKIE = "sessionCookie";

  @Bean
  public OpenAPI authServerOpenApi() {
    return new OpenAPI()
        .info(
            new Info()
                .title("auth-server API")
                .version("0.0.1")
                .description(
                    "Account, MFA, session and admin API of the OAuth 2.0 authorization server. "
                        + "OAuth 2.0 / OIDC protocol endpoints (/oauth2/*, /.well-known/*) follow "
                        + "the specifications and are described in API.md"))
        .components(
            new Components()
                .addSecuritySchemes(
                    BASIC_AUTH, new SecurityScheme().type(SecurityScheme.Type.HTTP).scheme("basic"))
                .addSecuritySchemes(
                    SESSION_COOKIE,
                    new SecurityScheme()
                        .type(SecurityScheme.Type.APIKEY)
                        .in(SecurityScheme.In.COOKIE)
                        .name("SESSION")))
        .addSecurityItem(new SecurityRequirement().addList(BASIC_AUTH));
  }
}
