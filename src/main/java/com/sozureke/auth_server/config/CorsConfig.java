package com.sozureke.auth_server.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableConfigurationProperties(CorsProperties.class)
public class CorsConfig {

  @Bean
  public CorsConfigurationSource corsConfigurationSource(CorsProperties properties) {
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    if (properties.allowedOrigins().isEmpty()) {
      return source;
    }
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(properties.allowedOrigins());
    configuration.setAllowedMethods(properties.allowedMethods());
    configuration.setAllowedHeaders(properties.allowedHeaders());
    configuration.setExposedHeaders(properties.exposedHeaders());
    configuration.setAllowCredentials(properties.allowCredentials());
    configuration.setMaxAge(properties.maxAge());
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }
}
