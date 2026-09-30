package com.sozureke.auth_server.logging;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.PatternLayout;
import ch.qos.logback.classic.spi.LoggingEvent;
import org.junit.jupiter.api.Test;

class MaskingMessageConverterTest {

  @Test
  void masksTokenInQueryString() {
    String masked =
        MaskingMessageConverter.mask("Verification link: /auth/verify?token=abc123def-456");

    assertThat(masked).isEqualTo("Verification link: /auth/verify?token=***");
  }

  @Test
  void masksPasswordAndKeepsTheRestOfTheLine() {
    String masked = MaskingMessageConverter.mask("login failed password=hunter2 for user 42");

    assertThat(masked).isEqualTo("login failed password=*** for user 42");
  }

  @Test
  void masksJsonStyleSecrets() {
    String masked =
        MaskingMessageConverter.mask(
            "{\"email\":\"a@example.com\",\"password\":\"hunter2\",\"client_secret\":\"s3cr3t\"}");

    assertThat(masked).doesNotContain("hunter2", "s3cr3t").contains("a@example.com");
  }

  @Test
  void masksAuthorizationHeaderCredentials() {
    assertThat(MaskingMessageConverter.mask("Authorization: Basic dXNlcjpwYXNzd29yZA=="))
        .doesNotContain("dXNlcjpwYXNzd29yZA")
        .contains("Basic ***");
    assertThat(MaskingMessageConverter.mask("header Bearer abcdef123456.ghijkl"))
        .doesNotContain("abcdef123456")
        .contains("Bearer ***");
  }

  @Test
  void masksJwts() {
    String jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl";

    assertThat(MaskingMessageConverter.mask("issued " + jwt + " to client"))
        .isEqualTo("issued *** to client");
  }

  @Test
  void masksRefreshAndAccessTokens() {
    String masked =
        MaskingMessageConverter.mask(
            "refresh_token=rt-value access_token: at-value code_verifier=cv");

    assertThat(masked).doesNotContain("rt-value", "at-value", "=cv");
  }

  @Test
  void leavesOrdinaryMessagesUntouched() {
    String message = "User 42 logged in from 10.0.0.1 in 35 ms";

    assertThat(MaskingMessageConverter.mask(message)).isEqualTo(message);
  }

  @Test
  void handlesNullAndEmpty() {
    assertThat(MaskingMessageConverter.mask(null)).isNull();
    assertThat(MaskingMessageConverter.mask("")).isEmpty();
  }

  @Test
  void replacesTheMessageWordInALogbackPattern_includingParameterizedMessages() {
    LoggerContext context = new LoggerContext();
    PatternLayout layout = new PatternLayout();
    layout.setContext(context);
    layout.getInstanceConverterMap().put("m", MaskingMessageConverter::new);
    layout.setPattern("%m");
    layout.start();

    LoggingEvent event =
        new LoggingEvent(
            LoggingEvent.class.getName(),
            context.getLogger("test"),
            Level.INFO,
            "reset link ?token={} for {}",
            null,
            new Object[] {"very-secret-token", "user-7"});

    assertThat(layout.doLayout(event)).isEqualTo("reset link ?token=*** for user-7");
  }
}
