package com.sozureke.auth_server.auth;

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
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {
  private static final Logger log = LoggerFactory.getLogger(AuthService.class);

  private static final int MAX_FAILED_ATTEMPTS = 5;
  private static final long LOCK_DURATION_MINUTES = 15;

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;

  public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
    this.userRepository = userRepository;
    this.passwordEncoder = passwordEncoder;
  }

  @Transactional
  public UserResponse login(String email, String rawPassword) {
    User user = userRepository.findByEmail(email).orElseThrow(InvalidCredentialsException::new);
    verifyCredentials(user, rawPassword);

    user.setFailedLoginAttempts(0);
    user.setLockedUntil(null);
    userRepository.save(user);

    return UserResponse.from(user);
  }

  @Transactional
  public UserResponse changePassword(String email, String currentPassword, String newPassword) {
    User user = userRepository.findByEmail(email).orElseThrow(InvalidCredentialsException::new);
    verifyCredentials(user, currentPassword);

    user.setPasswordHash(passwordEncoder.encode(newPassword));
    user.setFailedLoginAttempts(0);
    user.setLockedUntil(null);
    user.setResetToken(null);
    user.setResetTokenExpiresAt(null);
    userRepository.save(user);

    return UserResponse.from(user);
  }

  @Transactional
  public void requestPasswordReset(String email) {
    userRepository
        .findByEmail(email)
        .ifPresent(
            user -> {
              user.setResetToken(UUID.randomUUID().toString());
              user.setResetTokenExpiresAt(LocalDateTime.now().plusHours(1));
              userRepository.save(user);

              log.info("Password reset link: /auth/password-reset?token={}", user.getResetToken());
            });
  }

  @Transactional
  public void resetPassword(String token, String newPassword) {
    User user =
        userRepository
            .findByResetToken(token)
            .filter(
                u ->
                    u.getResetTokenExpiresAt() != null
                        && u.getResetTokenExpiresAt().isAfter(LocalDateTime.now()))
            .orElseThrow(() -> new InvalidResetTokenException(token));

    user.setPasswordHash(passwordEncoder.encode(newPassword));
    user.setResetToken(null);
    user.setResetTokenExpiresAt(null);
    user.setFailedLoginAttempts(0);
    user.setLockedUntil(null);
    userRepository.save(user);
  }

  public UserResponse getCurrentUser(String email) {
    User user = userRepository.findByEmail(email).orElseThrow(InvalidCredentialsException::new);
    return UserResponse.from(user);
  }

  @Transactional
  public UserResponse changeEmail(String currentEmail, String currentPassword, String newEmail) {
    User user =
        userRepository.findByEmail(currentEmail).orElseThrow(InvalidCredentialsException::new);
    verifyCredentials(user, currentPassword);

    if (!newEmail.equals(currentEmail) && userRepository.existsByEmail(newEmail))
      throw new EmailAlreadyExistsException(newEmail);

    user.setEmail(newEmail);
    user.setEmailVerified(false);
    user.setVerificationToken(UUID.randomUUID().toString());
    user.setResetToken(null);
    user.setResetTokenExpiresAt(null);
    userRepository.save(user);

    log.info("Verification link: /auth/verify?token={}", user.getVerificationToken());

    return UserResponse.from(user);
  }

  private void verifyCredentials(User user, String rawPassword) {
    if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(LocalDateTime.now()))
      throw new AccountLockedException(user.getEmail());

    if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
      registerFailedAttempt(user);
      throw new InvalidCredentialsException();
    }

    if (!user.isEmailVerified()) throw new EmailNotVerifiedException(user.getEmail());

    if (!user.isEnabled()) throw new AccountDisabledException(user.getEmail());
  }

  private void registerFailedAttempt(User user) {
    int attempts = user.getFailedLoginAttempts() + 1;
    user.setFailedLoginAttempts(attempts);

    if (attempts >= MAX_FAILED_ATTEMPTS)
      user.setLockedUntil(LocalDateTime.now().plusMinutes(LOCK_DURATION_MINUTES));

    userRepository.save(user);
  }
}
