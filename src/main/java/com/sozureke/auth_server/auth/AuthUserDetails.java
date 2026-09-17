package com.sozureke.auth_server.auth;

import com.sozureke.auth_server.user.User;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class AuthUserDetails implements UserDetails {
  private final User user;

  public AuthUserDetails(User user) {
    this.user = user;
  }

  public User getUser() {
    return user;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return user.getRoles().stream()
        .flatMap(
            role ->
                Stream.concat(
                    Stream.of(new SimpleGrantedAuthority("ROLE_" + role.getName())),
                    role.getPermissions().stream()
                        .map(permission -> new SimpleGrantedAuthority(permission.getName()))))
        .collect(Collectors.toSet());
  }

  @Override
  public String getUsername() {
    return user.getEmail();
  }

  @Override
  public String getPassword() {
    return user.getPasswordHash();
  }

  @Override
  public boolean isEnabled() {
    return user.isEnabled() && user.isEmailVerified();
  }

  @Override
  public boolean isAccountNonLocked() {
    return user.getLockedUntil() == null || user.getLockedUntil().isBefore(LocalDateTime.now());
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  public boolean isCredentialsNonExpired() {
    return true;
  }
}
