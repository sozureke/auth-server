package com.sozureke.auth_server.auth.exception;

public class AccountLockedException extends RuntimeException {

  public AccountLockedException(String email) {
    super("Account locked due to too many failed login attempts: %s".formatted(email));
  }
}
