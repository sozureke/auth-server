package com.sozureke.auth_server.auth.exception;

public class InvalidResetTokenException extends RuntimeException {

  public InvalidResetTokenException(String token) {
    super("Invalid or expired reset token: %s".formatted(token));
  }
}
