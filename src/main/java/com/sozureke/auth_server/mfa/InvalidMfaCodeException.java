package com.sozureke.auth_server.mfa;

public class InvalidMfaCodeException extends RuntimeException {

  public InvalidMfaCodeException() {
    super("Invalid MFA code");
  }
}
