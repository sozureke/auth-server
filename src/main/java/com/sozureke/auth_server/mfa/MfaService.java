package com.sozureke.auth_server.mfa;

import com.sozureke.auth_server.audit.AuditEventType;
import com.sozureke.auth_server.audit.AuditService;
import com.sozureke.auth_server.auth.exception.InvalidCredentialsException;
import com.sozureke.auth_server.mfa.dto.BackupCodesResponse;
import com.sozureke.auth_server.mfa.dto.MfaEnrollmentResponse;
import com.sozureke.auth_server.user.User;
import com.sozureke.auth_server.user.UserRepository;
import java.util.List;
import java.util.OptionalLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class MfaService {
  private static final Logger log = LoggerFactory.getLogger(MfaService.class);

  private final UserRepository userRepository;
  private final TotpService totpService;
  private final MfaSecretCipher cipher;
  private final QrCodeGenerator qrCodeGenerator;
  private final BackupCodeGenerator backupCodeGenerator;
  private final BackupCodeRepository backupCodeRepository;
  private final PasswordEncoder passwordEncoder;
  private final AuditService auditService;
  private final String issuer;

  public MfaService(
      UserRepository userRepository,
      TotpService totpService,
      MfaSecretCipher cipher,
      QrCodeGenerator qrCodeGenerator,
      BackupCodeRepository backupCodeRepository,
      BackupCodeGenerator backupCodeGenerator,
      PasswordEncoder passwordEncoder,
      AuditService auditService,
      @Value("${app.mfa.issuer:auth-server}") String issuer) {
    this.userRepository = userRepository;
    this.totpService = totpService;
    this.cipher = cipher;
    this.qrCodeGenerator = qrCodeGenerator;
    this.issuer = issuer;
    this.backupCodeGenerator = backupCodeGenerator;
    this.backupCodeRepository = backupCodeRepository;
    this.passwordEncoder = passwordEncoder;
    this.auditService = auditService;
  }

  @Transactional
  public MfaEnrollmentResponse startEnrollment(User user) {
    if (user.isMfaEnabled()) {
      throw new MfaAlreadyEnabledException();
    }

    byte[] secret = totpService.generateSecret();
    user.setTotpSecret(cipher.encrypt(secret));
    userRepository.save(user);

    String otpauthUri = totpService.otpauthUri(issuer, user.getEmail(), secret);
    return new MfaEnrollmentResponse(
        otpauthUri, totpService.encodeSecret(secret), qrCodeGenerator.pngDataUri(otpauthUri));
  }

  public byte[] pendingEnrollmentQr(User user) {
    byte[] secret = pendingSecret(user);
    return qrCodeGenerator.png(totpService.otpauthUri(issuer, user.getEmail(), secret));
  }

  @Transactional
  public BackupCodesResponse confirmEnrollment(User user, String code) {
    byte[] secret = pendingSecret(user);

    OptionalLong interval = totpService.verify(secret, code, user.getMfaLastUsedInterval());
    if (interval.isEmpty()
        || userRepository.advanceMfaInterval(user.getId(), interval.getAsLong()) == 0) {
      throw new InvalidMfaCodeException();
    }

    user.setMfaEnabled(true);
    userRepository.save(user);

    backupCodeRepository.deleteByUserId(user.getId());
    List<String> plainCodes = backupCodeGenerator.generate();
    List<BackupCode> entities =
        plainCodes.stream()
            .map(c -> new BackupCode(user.getId(), passwordEncoder.encode(c)))
            .toList();
    backupCodeRepository.saveAll(entities);

    auditService.log(
        user.getId(), AuditEventType.MFA_ENABLE, "user", user.getId().toString(), null);
    return new BackupCodesResponse(plainCodes);
  }

  @Transactional
  public boolean verifyLoginCode(User user, String code) {
    if (!user.isMfaEnabled()) {
      return false;
    }
    return verifyTotp(user, code) || verifyBackupCode(user, code);
  }

  private boolean verifyTotp(User user, String code) {
    if (user.getTotpSecret() == null) {
      return false;
    }
    byte[] secret;
    try {
      secret = cipher.decrypt(user.getTotpSecret());
    } catch (MfaSecretException e) {
      log.error("Stored TOTP secret for user {} is unreadable", user.getId(), e);
      return false;
    }

    OptionalLong interval = totpService.verify(secret, code, user.getMfaLastUsedInterval());
    return interval.isPresent()
        && userRepository.advanceMfaInterval(user.getId(), interval.getAsLong()) > 0;
  }

  @Transactional
  public void disable(User user, String password) {
    if (!user.isMfaEnabled()) {
      throw new MfaNotStartedException();
    }
    if (!passwordEncoder.matches(password, user.getPasswordHash())) {
      throw new InvalidCredentialsException();
    }

    user.setMfaEnabled(false);
    user.setTotpSecret(null);
    userRepository.save(user);
    backupCodeRepository.deleteByUserId(user.getId());

    auditService.log(
        user.getId(), AuditEventType.MFA_DISABLE, "user", user.getId().toString(), null);
  }

  private boolean verifyBackupCode(User user, String code) {
    for (BackupCode candidate : backupCodeRepository.findByUserIdAndUsedFalse(user.getId())) {
      if (passwordEncoder.matches(code, candidate.getCodeHash())) {
        return backupCodeRepository.markUsed(candidate.getId()) > 0;
      }
    }
    return false;
  }

  private byte[] pendingSecret(User user) {
    if (user.isMfaEnabled()) {
      throw new MfaAlreadyEnabledException();
    }
    if (user.getTotpSecret() == null) {
      throw new MfaNotStartedException();
    }
    try {
      return cipher.decrypt(user.getTotpSecret());
    } catch (MfaSecretException e) {
      log.error("Pending TOTP secret for user {} is unreadable", user.getId(), e);
      throw new MfaNotStartedException(); // fail closed: restart enrollment
    }
  }
}
