package com.sozureke.auth_server.config;

public class InvalidVerificationTokenException extends RuntimeException {
  public InvalidVerificationTokenException(String token) {
    super("Invalid or expired verification token: %s: ".formatted(token));
  }
}
