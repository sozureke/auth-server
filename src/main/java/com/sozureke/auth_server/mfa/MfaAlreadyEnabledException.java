package com.sozureke.auth_server.mfa;

public class MfaAlreadyEnabledException extends RuntimeException {

  public MfaAlreadyEnabledException() {
    super("MFA is already enabled");
  }
}
