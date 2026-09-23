package com.sozureke.auth_server.mfa;

public class MfaNotStartedException extends RuntimeException {

  public MfaNotStartedException() {
    super("MFA enrollment has not been started, call /auth/mfa/enable first");
  }
}
