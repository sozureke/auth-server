package com.sozureke.auth_server.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.sozureke.auth_server.role.Permission;
import com.sozureke.auth_server.role.Role;
import com.sozureke.auth_server.user.User;
import java.time.LocalDateTime;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

class AuthUserDetailsTest {

  private static final String EMAIL = "user@example.com";
  private static final String PASSWORD_HASH = "hashed-password";

  private User baseUser() {
    User user = new User(EMAIL, PASSWORD_HASH);
    user.setEmailVerified(true);
    user.setEnabled(true);
    return user;
  }

  @Test
  void getAuthorities_mapsRolesAndPermissions_toGrantedAuthorities() {
    Permission userRead = new Permission("USER_READ");
    Permission userWrite = new Permission("USER_WRITE");
    Role admin = new Role("ADMIN");
    admin.getPermissions().add(userRead);
    admin.getPermissions().add(userWrite);

    User user = baseUser();
    user.getRoles().add(admin);

    AuthUserDetails details = new AuthUserDetails(user);

    assertThat(details.getAuthorities())
        .extracting(GrantedAuthority::getAuthority)
        .containsExactlyInAnyOrder("ROLE_ADMIN", "USER_READ", "USER_WRITE");
  }

  @Test
  void getAuthorities_returnsEmpty_whenUserHasNoRoles() {
    AuthUserDetails details = new AuthUserDetails(baseUser());

    assertThat(details.getAuthorities()).isEmpty();
  }

  @Test
  void getUsername_returnsUserEmail() {
    AuthUserDetails details = new AuthUserDetails(baseUser());

    assertThat(details.getUsername()).isEqualTo(EMAIL);
  }

  @Test
  void getPassword_returnsPasswordHash() {
    AuthUserDetails details = new AuthUserDetails(baseUser());

    assertThat(details.getPassword()).isEqualTo(PASSWORD_HASH);
  }

  @Test
  void isEnabled_isFalse_whenAccountDisabled() {
    User user = baseUser();
    user.setEnabled(false);

    assertThat(new AuthUserDetails(user).isEnabled()).isFalse();
  }

  @Test
  void isEnabled_isFalse_whenEmailNotVerified() {
    User user = baseUser();
    user.setEmailVerified(false);

    assertThat(new AuthUserDetails(user).isEnabled()).isFalse();
  }

  @Test
  void isEnabled_isTrue_whenEnabledAndVerified() {
    assertThat(new AuthUserDetails(baseUser()).isEnabled()).isTrue();
  }

  @Test
  void isAccountNonLocked_isFalse_whenLockedUntilInFuture() {
    User user = baseUser();
    user.setLockedUntil(LocalDateTime.now().plusMinutes(5));

    assertThat(new AuthUserDetails(user).isAccountNonLocked()).isFalse();
  }

  @Test
  void isAccountNonLocked_isTrue_whenLockedUntilInPast() {
    User user = baseUser();
    user.setLockedUntil(LocalDateTime.now().minusMinutes(5));

    assertThat(new AuthUserDetails(user).isAccountNonLocked()).isTrue();
  }

  @Test
  void isAccountNonLocked_isTrue_whenLockedUntilNull() {
    assertThat(new AuthUserDetails(baseUser()).isAccountNonLocked()).isTrue();
  }
}
