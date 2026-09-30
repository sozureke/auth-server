package com.sozureke.auth_server.config;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("app.cors")
public record CorsProperties(
    List<String> allowedOrigins,
    List<String> allowedMethods,
    List<String> allowedHeaders,
    List<String> exposedHeaders,
    boolean allowCredentials,
    Duration maxAge) {

  public CorsProperties {
    allowedOrigins = allowedOrigins == null ? List.of() : List.copyOf(allowedOrigins);
    allowedMethods =
        allowedMethods == null || allowedMethods.isEmpty()
            ? List.of("GET", "POST", "PUT", "DELETE", "OPTIONS")
            : List.copyOf(allowedMethods);
    allowedHeaders =
        allowedHeaders == null || allowedHeaders.isEmpty()
            ? List.of("Authorization", "Content-Type", "Accept")
            : List.copyOf(allowedHeaders);
    exposedHeaders =
        exposedHeaders == null || exposedHeaders.isEmpty()
            ? List.of(
                "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "Retry-After")
            : List.copyOf(exposedHeaders);
    maxAge = maxAge == null ? Duration.ofHours(1) : maxAge;
    if (allowCredentials && allowedOrigins.contains("*")) {
      throw new IllegalArgumentException(
          "app.cors.allowed-origins cannot contain '*' together with allow-credentials=true");
    }
  }
}
