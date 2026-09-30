package com.sozureke.auth_server.auth;

import com.sozureke.auth_server.user.User;
import com.sozureke.auth_server.user.UserRepository;
import java.time.LocalDateTime;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class LoginAttemptService {

  public static final int MAX_FAILED_ATTEMPTS = 5;
  public static final long LOCK_DURATION_MINUTES = 15;

  private final UserRepository userRepository;

  public LoginAttemptService(UserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @Transactional
  public void recordFailure(String email) {
    userRepository.findByEmail(email).ifPresent(LoginAttemptService::registerFailure);
  }

  @Transactional
  public void recordSuccess(String email) {
    userRepository
        .findByEmail(email)
        .filter(user -> user.getFailedLoginAttempts() != 0 || user.getLockedUntil() != null)
        .ifPresent(
            user -> {
              user.setFailedLoginAttempts(0);
              user.setLockedUntil(null);
            });
  }

  static void registerFailure(User user) {
    int attempts = user.getFailedLoginAttempts() + 1;
    user.setFailedLoginAttempts(attempts);
    if (attempts >= MAX_FAILED_ATTEMPTS) {
      user.setLockedUntil(LocalDateTime.now().plusMinutes(LOCK_DURATION_MINUTES));
    }
  }
}
