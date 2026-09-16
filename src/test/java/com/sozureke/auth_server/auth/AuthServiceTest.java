package com.sozureke.auth_server.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sozureke.auth_server.auth.exception.AccountDisabledException;
import com.sozureke.auth_server.auth.exception.AccountLockedException;
import com.sozureke.auth_server.auth.exception.EmailNotVerifiedException;
import com.sozureke.auth_server.auth.exception.InvalidCredentialsException;
import com.sozureke.auth_server.user.User;
import com.sozureke.auth_server.user.UserRepository;
import com.sozureke.auth_server.user.dto.UserResponse;
import java.time.LocalDateTime;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

  private static final String EMAIL = "user@example.com";
  private static final String RAW_PASSWORD = "correct-password";
  private static final String PASSWORD_HASH = "hashed-password";

  @Mock private UserRepository userRepository;
  @Mock private PasswordEncoder passwordEncoder;

  private AuthService authService;

  @BeforeEach
  void setUp() {
    authService = new AuthService(userRepository, passwordEncoder);
  }

  private User verifiedEnabledUser() {
    User user = new User(EMAIL, PASSWORD_HASH);
    user.setEmailVerified(true);
    user.setEnabled(true);
    return user;
  }

  @Test
  void login_throwsInvalidCredentials_whenUserNotFound() {
    when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> authService.login(EMAIL, RAW_PASSWORD))
        .isInstanceOf(InvalidCredentialsException.class);
  }

  @Test
  void login_throwsAccountLocked_whenLockedUntilInFuture() {
    User user = verifiedEnabledUser();
    user.setLockedUntil(LocalDateTime.now().plusMinutes(5));
    when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));

    assertThatThrownBy(() -> authService.login(EMAIL, RAW_PASSWORD))
        .isInstanceOf(AccountLockedException.class);

    verify(passwordEncoder, never()).matches(any(), any());
  }

  @Test
  void login_throwsInvalidCredentials_andIncrementsAttempts_whenPasswordWrong() {
    User user = verifiedEnabledUser();
    user.setFailedLoginAttempts(1);
    when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
    when(passwordEncoder.matches(RAW_PASSWORD, PASSWORD_HASH)).thenReturn(false);

    assertThatThrownBy(() -> authService.login(EMAIL, RAW_PASSWORD))
        .isInstanceOf(InvalidCredentialsException.class);

    assertThat(user.getFailedLoginAttempts()).isEqualTo(2);
    assertThat(user.getLockedUntil()).isNull();
    verify(userRepository).save(user);
  }

  @Test
  void login_locksAccount_whenFailedAttemptsReachMax() {
    User user = verifiedEnabledUser();
    user.setFailedLoginAttempts(4);
    when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
    when(passwordEncoder.matches(RAW_PASSWORD, PASSWORD_HASH)).thenReturn(false);

    assertThatThrownBy(() -> authService.login(EMAIL, RAW_PASSWORD))
        .isInstanceOf(InvalidCredentialsException.class);

    assertThat(user.getFailedLoginAttempts()).isEqualTo(5);
    assertThat(user.getLockedUntil()).isAfter(LocalDateTime.now());
  }

  @Test
  void login_throwsEmailNotVerified_whenPasswordCorrectButNotVerified() {
    User user = new User(EMAIL, PASSWORD_HASH);
    user.setEmailVerified(false);
    user.setEnabled(true);
    when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
    when(passwordEncoder.matches(RAW_PASSWORD, PASSWORD_HASH)).thenReturn(true);

    assertThatThrownBy(() -> authService.login(EMAIL, RAW_PASSWORD))
        .isInstanceOf(EmailNotVerifiedException.class);
  }

  @Test
  void login_throwsAccountDisabled_whenVerifiedButDisabled() {
    User user = new User(EMAIL, PASSWORD_HASH);
    user.setEmailVerified(true);
    user.setEnabled(false);
    when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
    when(passwordEncoder.matches(RAW_PASSWORD, PASSWORD_HASH)).thenReturn(true);

    assertThatThrownBy(() -> authService.login(EMAIL, RAW_PASSWORD))
        .isInstanceOf(AccountDisabledException.class);
  }

  @Test
  void login_returnsUserResponse_andResetsAttempts_onSuccess() {
    User user = verifiedEnabledUser();
    user.setFailedLoginAttempts(3);
    when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
    when(passwordEncoder.matches(RAW_PASSWORD, PASSWORD_HASH)).thenReturn(true);

    UserResponse response = authService.login(EMAIL, RAW_PASSWORD);

    assertThat(response.email()).isEqualTo(EMAIL);
    assertThat(user.getFailedLoginAttempts()).isZero();
    assertThat(user.getLockedUntil()).isNull();
    verify(userRepository).save(user);
  }
}
