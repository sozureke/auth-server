package com.sozureke.auth_server.auth;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class LoginAttemptListener {

  private final LoginAttemptService loginAttemptService;

  public LoginAttemptListener(LoginAttemptService loginAttemptService) {
    this.loginAttemptService = loginAttemptService;
  }

  @EventListener
  public void onBadCredentials(AuthenticationFailureBadCredentialsEvent event) {
    loginAttemptService.recordFailure(event.getAuthentication().getName());
  }

  @EventListener
  public void onSuccess(AuthenticationSuccessEvent event) {
    if (event.getAuthentication().getPrincipal() instanceof AuthUserDetails details
        && details.getUser().getFailedLoginAttempts() == 0
        && details.getUser().getLockedUntil() == null) {
      return;
    }
    loginAttemptService.recordSuccess(event.getAuthentication().getName());
  }
}
