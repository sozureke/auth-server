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
import com.sozureke.auth_server.auth.exception.InvalidResetTokenException;
import com.sozureke.auth_server.user.EmailAlreadyExistsException;
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
  private static final String NEW_RAW_PASSWORD = "new-correct-password";
  private static final String NEW_PASSWORD_HASH = "new-hashed-password";

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

  @Test
  void changePassword_throwsInvalidCredentials_whenUserNotFound() {
    when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> authService.changePassword(EMAIL, RAW_PASSWORD, NEW_RAW_PASSWORD))
        .isInstanceOf(InvalidCredentialsException.class);
  }

  @Test
  void changePassword_throwsAccountLocked_whenLockedUntilInFuture() {
    User user = verifiedEnabledUser();
    user.setLockedUntil(LocalDateTime.now().plusMinutes(5));
    when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));

    assertThatThrownBy(() -> authService.changePassword(EMAIL, RAW_PASSWORD, NEW_RAW_PASSWORD))
        .isInstanceOf(AccountLockedException.class);

    verify(passwordEncoder, never()).matches(any(), any());
  }

  @Test
  void changePassword_throwsInvalidCredentials_andIncrementsAttempts_whenCurrentPasswordWrong() {
    User user = verifiedEnabledUser();
    user.setFailedLoginAttempts(1);
    when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
    when(passwordEncoder.matches(RAW_PASSWORD, PASSWORD_HASH)).thenReturn(false);

    assertThatThrownBy(() -> authService.changePassword(EMAIL, RAW_PASSWORD, NEW_RAW_PASSWORD))
        .isInstanceOf(InvalidCredentialsException.class);

    assertThat(user.getFailedLoginAttempts()).isEqualTo(2);
    verify(userRepository).save(user);
  }

  @Test
  void changePassword_throwsEmailNotVerified_whenPasswordCorrectButNotVerified() {
    User user = new User(EMAIL, PASSWORD_HASH);
    user.setEmailVerified(false);
    user.setEnabled(true);
    when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
    when(passwordEncoder.matches(RAW_PASSWORD, PASSWORD_HASH)).thenReturn(true);

    assertThatThrownBy(() -> authService.changePassword(EMAIL, RAW_PASSWORD, NEW_RAW_PASSWORD))
        .isInstanceOf(EmailNotVerifiedException.class);
  }

  @Test
  void changePassword_throwsAccountDisabled_whenVerifiedButDisabled() {
    User user = new User(EMAIL, PASSWORD_HASH);
    user.setEmailVerified(true);
    user.setEnabled(false);
    when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
    when(passwordEncoder.matches(RAW_PASSWORD, PASSWORD_HASH)).thenReturn(true);

    assertThatThrownBy(() -> authService.changePassword(EMAIL, RAW_PASSWORD, NEW_RAW_PASSWORD))
        .isInstanceOf(AccountDisabledException.class);
  }

  @Test
  void changePassword_updatesHash_clearsResetToken_andResetsAttempts_onSuccess() {
    User user = verifiedEnabledUser();
    user.setFailedLoginAttempts(3);
    user.setResetToken("stale-reset-token");
    user.setResetTokenExpiresAt(LocalDateTime.now().plusMinutes(30));
    when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
    when(passwordEncoder.matches(RAW_PASSWORD, PASSWORD_HASH)).thenReturn(true);
    when(passwordEncoder.encode(NEW_RAW_PASSWORD)).thenReturn(NEW_PASSWORD_HASH);

    UserResponse response = authService.changePassword(EMAIL, RAW_PASSWORD, NEW_RAW_PASSWORD);

    assertThat(response.email()).isEqualTo(EMAIL);
    assertThat(user.getPasswordHash()).isEqualTo(NEW_PASSWORD_HASH);
    assertThat(user.getFailedLoginAttempts()).isZero();
    assertThat(user.getLockedUntil()).isNull();
    assertThat(user.getResetToken()).isNull();
    assertThat(user.getResetTokenExpiresAt()).isNull();
    verify(userRepository).save(user);
  }

  @Test
  void requestPasswordReset_doesNothing_whenUserNotFound() {
    when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

    authService.requestPasswordReset(EMAIL);

    verify(userRepository, never()).save(any());
  }

  @Test
  void requestPasswordReset_setsTokenAndExpiry_whenUserFound() {
    User user = verifiedEnabledUser();
    when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));

    authService.requestPasswordReset(EMAIL);

    assertThat(user.getResetToken()).isNotBlank();
    assertThat(user.getResetTokenExpiresAt()).isAfter(LocalDateTime.now());
    verify(userRepository).save(user);
  }

  @Test
  void resetPassword_throwsInvalidResetToken_whenTokenNotFound() {
    when(userRepository.findByResetToken("bad-token")).thenReturn(Optional.empty());

    assertThatThrownBy(() -> authService.resetPassword("bad-token", NEW_RAW_PASSWORD))
        .isInstanceOf(InvalidResetTokenException.class);
  }

  @Test
  void resetPassword_throwsInvalidResetToken_whenTokenExpired() {
    User user = verifiedEnabledUser();
    user.setResetToken("expired-token");
    user.setResetTokenExpiresAt(LocalDateTime.now().minusMinutes(1));
    when(userRepository.findByResetToken("expired-token")).thenReturn(Optional.of(user));

    assertThatThrownBy(() -> authService.resetPassword("expired-token", NEW_RAW_PASSWORD))
        .isInstanceOf(InvalidResetTokenException.class);

    verify(userRepository, never()).save(any());
  }

  @Test
  void resetPassword_updatesHash_clearsToken_andResetsLockout_whenTokenValid() {
    User user = verifiedEnabledUser();
    user.setResetToken("valid-token");
    user.setResetTokenExpiresAt(LocalDateTime.now().plusMinutes(30));
    user.setFailedLoginAttempts(4);
    user.setLockedUntil(LocalDateTime.now().plusMinutes(10));
    when(userRepository.findByResetToken("valid-token")).thenReturn(Optional.of(user));
    when(passwordEncoder.encode(NEW_RAW_PASSWORD)).thenReturn(NEW_PASSWORD_HASH);

    authService.resetPassword("valid-token", NEW_RAW_PASSWORD);

    assertThat(user.getPasswordHash()).isEqualTo(NEW_PASSWORD_HASH);
    assertThat(user.getResetToken()).isNull();
    assertThat(user.getResetTokenExpiresAt()).isNull();
    assertThat(user.getFailedLoginAttempts()).isZero();
    assertThat(user.getLockedUntil()).isNull();
    verify(userRepository).save(user);
  }

  @Test
  void changeEmail_throwsAccountLocked_whenLockedUntilInFuture() {
    User user = verifiedEnabledUser();
    user.setLockedUntil(LocalDateTime.now().plusMinutes(5));

    assertThatThrownBy(() -> authService.changeEmail(user, RAW_PASSWORD, "new@example.com"))
        .isInstanceOf(AccountLockedException.class);

    verify(passwordEncoder, never()).matches(any(), any());
  }

  @Test
  void changeEmail_throwsInvalidCredentials_andIncrementsAttempts_whenCurrentPasswordWrong() {
    User user = verifiedEnabledUser();
    user.setFailedLoginAttempts(1);
    when(passwordEncoder.matches(RAW_PASSWORD, PASSWORD_HASH)).thenReturn(false);

    assertThatThrownBy(() -> authService.changeEmail(user, RAW_PASSWORD, "new@example.com"))
        .isInstanceOf(InvalidCredentialsException.class);

    assertThat(user.getFailedLoginAttempts()).isEqualTo(2);
    verify(userRepository).save(user);
  }

  @Test
  void changeEmail_throwsEmailAlreadyExists_whenNewEmailTaken() {
    User user = verifiedEnabledUser();
    when(passwordEncoder.matches(RAW_PASSWORD, PASSWORD_HASH)).thenReturn(true);
    when(userRepository.existsByEmail("taken@example.com")).thenReturn(true);

    assertThatThrownBy(() -> authService.changeEmail(user, RAW_PASSWORD, "taken@example.com"))
        .isInstanceOf(EmailAlreadyExistsException.class);
  }

  @Test
  void changeEmail_updatesEmail_resetsVerification_andClearsResetToken_onSuccess() {
    User user = verifiedEnabledUser();
    user.setResetToken("stale-reset-token");
    user.setResetTokenExpiresAt(LocalDateTime.now().plusMinutes(30));
    when(passwordEncoder.matches(RAW_PASSWORD, PASSWORD_HASH)).thenReturn(true);
    when(userRepository.existsByEmail("new@example.com")).thenReturn(false);

    UserResponse response = authService.changeEmail(user, RAW_PASSWORD, "new@example.com");

    assertThat(response.email()).isEqualTo("new@example.com");
    assertThat(user.getEmail()).isEqualTo("new@example.com");
    assertThat(user.isEmailVerified()).isFalse();
    assertThat(user.getVerificationToken()).isNotBlank();
    assertThat(user.getResetToken()).isNull();
    assertThat(user.getResetTokenExpiresAt()).isNull();
    verify(userRepository).save(user);
  }
}
