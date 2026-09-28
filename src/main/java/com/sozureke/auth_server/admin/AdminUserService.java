package com.sozureke.auth_server.admin;

import com.sozureke.auth_server.audit.AuditEventType;
import com.sozureke.auth_server.audit.AuditService;
import com.sozureke.auth_server.mfa.BackupCodeRepository;
import com.sozureke.auth_server.session.SessionManagementService;
import com.sozureke.auth_server.user.User;
import com.sozureke.auth_server.user.UserRepository;
import java.util.Map;
import java.util.Set;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AdminUserService {
  public static final Set<String> SORTABLE = Set.of("id", "email", "createdAt", "enabled");
  private final UserRepository userRepository;
  private final BackupCodeRepository backupCodeRepository;
  private final SessionManagementService sessionManagementService;
  private final AuditService auditService;

  public AdminUserService(
      UserRepository userRepository,
      BackupCodeRepository backupCodeRepository,
      SessionManagementService sessionManagementService,
      AuditService auditService) {
    this.userRepository = userRepository;
    this.backupCodeRepository = backupCodeRepository;
    this.sessionManagementService = sessionManagementService;
    this.auditService = auditService;
  }

  @Transactional(readOnly = true)
  public Page<User> search(String query, Pageable pageable) {
    SortWhitelist.check(pageable, SORTABLE);
    return userRepository.search(likePattern(query), pageable);
  }

  @Transactional(readOnly = true)
  public User get(Long id) {
    return userRepository.findById(id).orElseThrow(UserNotFoundException::new);
  }

  @Transactional
  public User disable(Long actorId, Long id) {
    rejectSelf(actorId, id, "disable");
    User user = get(id);
    user.setEnabled(false);
    userRepository.save(user);
    sessionManagementService.revokeAll(user.getEmail());
    auditService.log(actorId, AuditEventType.USER_DISABLED, "user", id.toString(), Map.of());
    return user;
  }

  @Transactional
  public void delete(Long actorId, Long id) {
    rejectSelf(actorId, id, "delete");
    User user = get(id);
    sessionManagementService.revokeAll(user.getEmail());
    backupCodeRepository.deleteByUserId(id);
    userRepository.delete(user);
    auditService.log(actorId, AuditEventType.USER_DELETED, "user", id.toString(), Map.of());
  }

  public int forceLogout(Long actorId, Long id) {
    User user = get(id);
    int revoked = sessionManagementService.revokeAll(user.getEmail());
    auditService.log(
        actorId,
        AuditEventType.USER_FORCE_LOGOUT,
        "user",
        id.toString(),
        Map.of("sessionsRevoked", revoked));
    return revoked;
  }

  private static void rejectSelf(Long actorId, Long targetId, String action) {
    if (actorId.equals(targetId)) {
      throw new AdminActionNotAllowedException("Admins cannot " + action + " their own account");
    }
  }

  private static String likePattern(String query) {
    if (query == null || query.isBlank()) {
      return null;
    }
    String escaped =
        query.trim().toLowerCase().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    return "%" + escaped + "%";
  }
}
