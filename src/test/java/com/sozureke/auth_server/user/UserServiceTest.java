package com.sozureke.auth_server.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sozureke.auth_server.config.InvalidVerificationTokenException;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

  private static final String EMAIL = "user@example.com";
  private static final String RAW_PASSWORD = "correct-password";
  private static final String PASSWORD_HASH = "hashed-password";

  @Mock private UserRepository userRepository;
  @Mock private PasswordEncoder passwordEncoder;

  private UserService userService;

  @BeforeEach
  void setUp() {
    userService = new UserService(userRepository, passwordEncoder);
  }

  @Test
  void register_throwsEmailAlreadyExists_whenEmailTaken() {
    when(userRepository.existsByEmail(EMAIL)).thenReturn(true);

    assertThatThrownBy(() -> userService.register(EMAIL, RAW_PASSWORD))
        .isInstanceOf(EmailAlreadyExistsException.class);

    verify(userRepository, org.mockito.Mockito.never()).save(any());
  }

  @Test
  void register_savesUser_withHashedPasswordAndVerificationToken() {
    when(userRepository.existsByEmail(EMAIL)).thenReturn(false);
    when(passwordEncoder.encode(RAW_PASSWORD)).thenReturn(PASSWORD_HASH);
    when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

    User savedUser = userService.register(EMAIL, RAW_PASSWORD);

    assertThat(savedUser.getEmail()).isEqualTo(EMAIL);
    assertThat(savedUser.getPasswordHash()).isEqualTo(PASSWORD_HASH);
    assertThat(savedUser.getVerificationToken()).isNotBlank();
    assertThat(savedUser.isEmailVerified()).isFalse();
  }

  @Test
  void verifyEmail_throwsInvalidVerificationToken_whenTokenNotFound() {
    when(userRepository.findByVerificationToken("bad-token")).thenReturn(Optional.empty());

    assertThatThrownBy(() -> userService.verifyEmail("bad-token"))
        .isInstanceOf(InvalidVerificationTokenException.class);
  }

  @Test
  void verifyEmail_marksVerified_andClearsToken_whenTokenValid() {
    User user = new User(EMAIL, PASSWORD_HASH);
    user.setVerificationToken("valid-token");
    when(userRepository.findByVerificationToken("valid-token")).thenReturn(Optional.of(user));
    when(userRepository.save(user)).thenReturn(user);

    User result = userService.verifyEmail("valid-token");

    assertThat(result.isEmailVerified()).isTrue();
    assertThat(result.getVerificationToken()).isNull();
    verify(userRepository).save(user);
  }
}
