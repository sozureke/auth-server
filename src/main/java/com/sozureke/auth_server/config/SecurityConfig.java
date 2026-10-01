package com.sozureke.auth_server.config;

import com.sozureke.auth_server.ratelimit.ApiRateLimitFilter;
import com.sozureke.auth_server.ratelimit.RateLimitProperties;
import com.sozureke.auth_server.ratelimit.RateLimiter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import tools.jackson.databind.ObjectMapper;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

  @Bean
  @Order(2)
  public SecurityFilterChain securityFilterChain(
      HttpSecurity http,
      RateLimiter rateLimiter,
      RateLimitProperties rateLimitProperties,
      ObjectMapper objectMapper)
      throws Exception {
    http.cors(Customizer.withDefaults())
        .csrf(csrf -> csrf.disable())
        .authorizeHttpRequests(
            authorize ->
                authorize
                    .requestMatchers(
                        "/auth/register",
                        "/auth/verify",
                        "/auth/login",
                        "/auth/password",
                        "/auth/password-reset-request",
                        "/auth/password-reset")
                    .permitAll()
                    .requestMatchers("/actuator/health", "/actuator/health/**")
                    .permitAll()
                    .requestMatchers(
                        "/v3/api-docs", "/v3/api-docs/**", "/swagger-ui.html", "/swagger-ui/**")
                    .permitAll()
                    .requestMatchers("/api/admin/**")
                    .hasAnyAuthority("USER_READ", "USER_WRITE", "CLIENT_MANAGE", "AUDIT_READ")
                    .requestMatchers("/api/clients/**", "/api/clients")
                    .hasRole("ADMIN")
                    .anyRequest()
                    .authenticated())
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .httpBasic(basic -> {})
        .addFilterAfter(
            new ApiRateLimitFilter(rateLimiter, rateLimitProperties, objectMapper),
            BasicAuthenticationFilter.class);

    return http.build();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);
  }
}
