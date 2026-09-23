package com.sozureke.auth_server.mfa;

import java.security.SecureRandom;
import java.util.List;
import java.util.stream.IntStream;
import org.springframework.stereotype.Component;

@Component
public class BackupCodeGenerator {
  private static final int CODE_COUNT = 10;
  private static final String ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  private static final SecureRandom RANDOM = new SecureRandom();

  public List<String> generate() {
    return IntStream.range(0, CODE_COUNT).mapToObj(i -> generateOne()).toList();
  }

  private String generateOne() {
    StringBuilder sb = new StringBuilder(9);
    for (int i = 0; i < 8; i++) {
      if (i == 4) sb.append('-');
      sb.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
    }
    return sb.toString();
  }
}
