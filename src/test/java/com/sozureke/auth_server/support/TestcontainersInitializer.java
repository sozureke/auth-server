package com.sozureke.auth_server.support;

import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.lifecycle.Startables;
import org.testcontainers.postgresql.PostgreSQLContainer;

public class TestcontainersInitializer
    implements ApplicationContextInitializer<ConfigurableApplicationContext> {

  private static final PostgreSQLContainer POSTGRES =
      new PostgreSQLContainer("postgres:15")
          .withDatabaseName("authdb_test")
          .withUsername("auth_test")
          .withPassword("auth_test")
          .withCommand("postgres", "-c", "max_connections=300");

  private static final GenericContainer<?> REDIS =
      new GenericContainer<>("redis:7").withExposedPorts(6379);

  static {
    Startables.deepStart(POSTGRES, REDIS).join();
  }

  @Override
  public void initialize(ConfigurableApplicationContext context) {
    TestPropertyValues.of(
            "DB_HOST=" + POSTGRES.getHost(),
            "DB_PORT=" + POSTGRES.getMappedPort(5432),
            "DB_NAME=" + POSTGRES.getDatabaseName(),
            "DB_USER=" + POSTGRES.getUsername(),
            "DB_PASSWORD=" + POSTGRES.getPassword(),
            "REDIS_HOST=" + REDIS.getHost(),
            "REDIS_PORT=" + REDIS.getMappedPort(6379),
            "APP_PORT=8080",
            "spring.datasource.hikari.maximum-pool-size=4",
            "MFA_ENCRYPTION_KEY=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
        .applyTo(context.getEnvironment());
  }
}
