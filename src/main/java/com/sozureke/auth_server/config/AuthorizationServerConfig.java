package com.sozureke.auth_server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.sozureke.auth_server.auth.AuthUserDetails;
import com.sozureke.auth_server.mfa.MfaAccessDeniedHandler;
import com.sozureke.auth_server.mfa.MfaVerificationRequiredAuthorizationManager;
import com.sozureke.auth_server.role.Permission;
import com.sozureke.auth_server.role.Role;
import com.sozureke.auth_server.session.SessionMetadataAuthenticationSuccessHandler;
import com.sozureke.auth_server.user.User;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import tools.jackson.databind.ObjectMapper;

@Configuration
public class AuthorizationServerConfig {

  @Bean
  public RequestCache requestCache() {
    return new HttpSessionRequestCache();
  }

  @Bean
  @Order(1)
  public SecurityFilterChain authorizationServerSecurityFilterChain(
      HttpSecurity http, RequestCache requestCache, ObjectMapper objectMapper) throws Exception {
    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
        new OAuth2AuthorizationServerConfigurer();

    RequestMatcher authorizeEndpointMatcher =
        PathPatternRequestMatcher.pathPattern("/oauth2/authorize");
    RequestMatcher matcher =
        new OrRequestMatcher(
            authorizationServerConfigurer.getEndpointsMatcher(),
            PathPatternRequestMatcher.pathPattern("/login"),
            PathPatternRequestMatcher.pathPattern("/login/totp"),
            PathPatternRequestMatcher.pathPattern("/auth/sessions"),
            PathPatternRequestMatcher.pathPattern("/auth/sessions/*"));

    http.securityMatcher(matcher)
        .with(authorizationServerConfigurer, (server) -> server.oidc(Customizer.withDefaults()))
        .authorizeHttpRequests(
            authorize ->
                authorize
                    .requestMatchers(authorizeEndpointMatcher)
                    .access(
                        AuthorizationManagers.allOf(
                            AuthenticatedAuthorizationManager.authenticated(),
                            new MfaVerificationRequiredAuthorizationManager()))
                    .anyRequest()
                    .authenticated())
        .exceptionHandling(
            exceptions ->
                exceptions.defaultAccessDeniedHandlerFor(
                    new MfaAccessDeniedHandler(requestCache, objectMapper),
                    authorizeEndpointMatcher))
        .formLogin(
            form ->
                form.successHandler(new SessionMetadataAuthenticationSuccessHandler(requestCache)));

    return http.build();
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings(
      @Value("${app.issuer-uri}") String issuerUri) {
    return AuthorizationServerSettings.builder().issuer(issuerUri).build();
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    KeyPair keyPair = generateRsaKey();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    RSAKey rsaKey =
        new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
    return new ImmutableJWKSet<>(new JWKSet(rsaKey));
  }

  @Bean
  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  private static KeyPair generateRsaKey() {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048);
      return generator.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  @Bean
  public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
    return context -> {
      if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
        return;
      }

      Authentication principal = context.getPrincipal();
      if (principal.getPrincipal() instanceof AuthUserDetails authUserDetails) {
        User user = authUserDetails.getUser();

        Set<String> roles = user.getRoles().stream().map(Role::getName).collect(Collectors.toSet());
        Set<String> permissions =
            user.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(Permission::getName)
                .collect(Collectors.toSet());

        context.getClaims().claim("roles", roles).claim("permissions", permissions);
      }
    };
  }
}
