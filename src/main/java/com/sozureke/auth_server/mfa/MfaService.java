package com.sozureke.auth_server.mfa;

import com.sozureke.auth_server.mfa.dto.MfaEnrollmentResponse;
import com.sozureke.auth_server.user.User;
import com.sozureke.auth_server.user.UserRepository;
import java.util.OptionalLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class MfaService {
  private static final Logger log = LoggerFactory.getLogger(MfaService.class);

  private final UserRepository userRepository;
  private final TotpService totpService;
  private final MfaSecretCipher cipher;
  private final QrCodeGenerator qrCodeGenerator;
  private final String issuer;

  public MfaService(
      UserRepository userRepository,
      TotpService totpService,
      MfaSecretCipher cipher,
      QrCodeGenerator qrCodeGenerator,
      @Value("${app.mfa.issuer:auth-server}") String issuer) {
    this.userRepository = userRepository;
    this.totpService = totpService;
    this.cipher = cipher;
    this.qrCodeGenerator = qrCodeGenerator;
    this.issuer = issuer;
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
  public void confirmEnrollment(User user, String code) {
    byte[] secret = pendingSecret(user);

    OptionalLong interval = totpService.verify(secret, code, user.getMfaLastUsedInterval());
    if (interval.isEmpty()
        || userRepository.advanceMfaInterval(user.getId(), interval.getAsLong()) == 0) {
      throw new InvalidMfaCodeException();
    }

    user.setMfaEnabled(true);
    userRepository.save(user);
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
