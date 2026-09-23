package com.sozureke.auth_server.mfa;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class MfaConfig {
  @Bean
  public Clock clock() {
    return Clock.systemUTC();
  }
}
