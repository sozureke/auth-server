package com.sozureke.auth_server.auth.exception;

public class AccountDisabledException extends RuntimeException {

  public AccountDisabledException(String email) {
    super("Account disabled: %s".formatted(email));
  }
}
