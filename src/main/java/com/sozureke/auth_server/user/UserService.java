package com.sozureke.auth_server.user;

import com.sozureke.auth_server.audit.AuditEventType;
import com.sozureke.auth_server.audit.AuditService;
import com.sozureke.auth_server.config.InvalidVerificationTokenException;
import com.sozureke.auth_server.role.Role;
import com.sozureke.auth_server.role.RoleRepository;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {
  private static final Logger log = LoggerFactory.getLogger(UserService.class);

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final RoleRepository roleRepository;
  private final AuditService auditService;

  public UserService(
      UserRepository userRepository,
      PasswordEncoder passwordEncoder,
      RoleRepository roleRepository,
      AuditService auditService) {
    this.userRepository = userRepository;
    this.passwordEncoder = passwordEncoder;
    this.roleRepository = roleRepository;
    this.auditService = auditService;
  }

  public User register(String email, String rawPassword) {
    if (userRepository.existsByEmail(email)) throw new EmailAlreadyExistsException(email);

    String passwordHash = passwordEncoder.encode(rawPassword);

    User user = new User(email, passwordHash);

    user.setVerificationToken(UUID.randomUUID().toString());

    Role userRole =
        roleRepository
            .findByName("USER")
            .orElseThrow(() -> new IllegalStateException("Default role USER not seeded"));
    user.getRoles().add(userRole);

    User savedUser = userRepository.save(user);

    auditService.log(
        savedUser.getId(),
        AuditEventType.REGISTER,
        "user",
        savedUser.getId().toString(),
        Map.of("email", email));
    log.info("Verification link: /auth/verify?token={}", savedUser.getVerificationToken());
    return savedUser;
  }

  public User verifyEmail(String token) {
    Optional<User> userResult = userRepository.findByVerificationToken(token);
    if (userResult.isEmpty()) throw new InvalidVerificationTokenException(token);

    User user = userResult.get();

    user.setEmailVerified(true);
    user.setVerificationToken(null);

    return userRepository.save(user);
  }
}
