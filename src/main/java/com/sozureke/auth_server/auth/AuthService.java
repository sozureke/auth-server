package com.sozureke.auth_server.auth;

import com.sozureke.auth_server.auth.exception.AccountDisabledException;
import com.sozureke.auth_server.auth.exception.AccountLockedException;
import com.sozureke.auth_server.auth.exception.EmailNotVerifiedException;
import com.sozureke.auth_server.auth.exception.InvalidCredentialsException;
import com.sozureke.auth_server.user.User;
import com.sozureke.auth_server.user.UserRepository;
import com.sozureke.auth_server.user.dto.UserResponse;
import java.time.LocalDateTime;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {
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

    if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(LocalDateTime.now()))
      throw new AccountLockedException(user.getEmail());

    if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
      registerFailedAttempt(user);
      throw new InvalidCredentialsException();
    }

    if (!user.isEmailVerified()) throw new EmailNotVerifiedException(user.getEmail());

    if (!user.isEnabled()) throw new AccountDisabledException(user.getEmail());

    user.setFailedLoginAttempts(0);
    user.setLockedUntil(null);
    userRepository.save(user);

    return UserResponse.from(user);
  }

  private void registerFailedAttempt(User user) {
    int attempts = user.getFailedLoginAttempts() + 1;
    user.setFailedLoginAttempts(attempts);

    if (attempts >= MAX_FAILED_ATTEMPTS)
      user.setLockedUntil(LocalDateTime.now().plusMinutes(LOCK_DURATION_MINUTES));

    userRepository.save(user);
  }
}
