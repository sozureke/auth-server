package com.sozureke.auth_server.ratelimit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.jackson.databind.ObjectMapper;

@Configuration
@EnableConfigurationProperties(RateLimitProperties.class)
public class RateLimitConfig {

  @Bean
  public FilterRegistrationBean<RateLimitFilter> rateLimitFilterRegistration(
      RateLimiter rateLimiter,
      RateLimitProperties properties,
      ObjectMapper objectMapper,
      @Value("${spring.security.filter.order:-100}") int securityFilterOrder) {
    FilterRegistrationBean<RateLimitFilter> registration =
        new FilterRegistrationBean<>(new RateLimitFilter(rateLimiter, properties, objectMapper));
    // Lower value = earlier. Must run before Spring Security's filter chain proxy so that both
    // security chains (session and Basic) are covered and rejected requests are still counted.
    registration.setOrder(securityFilterOrder - 1);
    return registration;
  }
}
