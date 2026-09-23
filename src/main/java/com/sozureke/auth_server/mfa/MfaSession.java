package com.sozureke.auth_server.mfa;

import jakarta.servlet.http.HttpSession;
import java.time.Instant;

public final class MfaSession {

  public static final String VERIFIED_AT_ATTRIBUTE = "MFA_VERIFIED_AT";

  private MfaSession() {}

  public static void markVerified(HttpSession session) {
    session.setAttribute(VERIFIED_AT_ATTRIBUTE, Instant.now());
  }

  public static boolean isVerified(HttpSession session) {
    return session != null && session.getAttribute(VERIFIED_AT_ATTRIBUTE) != null;
  }
}
