package com.sozureke.auth_server.mfa;

public class MfaSecretException extends RuntimeException {
  public MfaSecretException(String message, Throwable cause) {
    super(message, cause);
  }
}
