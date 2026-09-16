package com.sozureke.auth_server.auth.exception;

public class EmailNotVerifiedException extends RuntimeException {

  public EmailNotVerifiedException(String email) {
    super("Email not verified: %s".formatted(email));
  }
}
