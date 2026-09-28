package com.sozureke.auth_server.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sozureke.auth_server.audit.AuditService;
import com.sozureke.auth_server.auth.exception.InvalidCredentialsException;
import com.sozureke.auth_server.mfa.dto.BackupCodesResponse;
import com.sozureke.auth_server.mfa.dto.MfaEnrollmentResponse;
import com.sozureke.auth_server.user.User;
import com.sozureke.auth_server.user.UserRepository;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.apache.commons.codec.binary.Base32;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class MfaServiceTest {

  private static final byte[] RFC_SECRET =
      "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
  private static final long NOW = 1234567890L;
  private static final long NOW_INTERVAL = 41152263L;
  private static final String CODE_NOW = "005924";

  @Mock private UserRepository userRepository;
  @Mock private BackupCodeRepository backupCodeRepository;
  @Mock private AuditService auditService;

  private MfaSecretCipher cipher;
  private PasswordEncoder passwordEncoder;
  private MfaService service;

  @BeforeEach
  void setUp() {
    byte[] key = new byte[32];
    Arrays.fill(key, (byte) 7);
    cipher = new MfaSecretCipher(Base64.getEncoder().encodeToString(key));
    passwordEncoder = new BCryptPasswordEncoder(4); // low cost factor: tests only

    Clock clock = Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC);
    service =
        new MfaService(
            userRepository,
            new TotpService(clock),
            cipher,
            new QrCodeGenerator(),
            backupCodeRepository,
            new BackupCodeGenerator(),
            passwordEncoder,
            auditService,
            "Test Issuer");
  }

  private BackupCode backupCodeEntity(long id, String plainCode) {
    BackupCode entity = new BackupCode(1L, passwordEncoder.encode(plainCode));
    entity.setId(id);
    return entity;
  }

  private User userWithPendingSecret() {
    User user = new User("alice@example.com", "hash");
    user.setId(1L);
    user.setTotpSecret(cipher.encrypt(RFC_SECRET));
    return user;
  }

  // --- startEnrollment
  // -------------------------------------------------------------------------

  @Test
  void startEnrollment_storesEncryptedSecret_andReturnsUriAndManualKey() {
    User user = new User("alice@example.com", "hash");

    MfaEnrollmentResponse response = service.startEnrollment(user);

    assertThat(user.getTotpSecret()).isNotBlank();
    assertThat(user.isMfaEnabled()).isFalse(); // pending until verify-setup succeeds
    byte[] stored = cipher.decrypt(user.getTotpSecret());
    assertThat(stored).hasSize(20);
    assertThat(response.manualEntryKey()).isEqualTo(new Base32().encodeToString(stored));
    assertThat(response.otpauthUri())
        .startsWith("otpauth://totp/Test%20Issuer:alice@example.com?")
        .contains("secret=" + response.manualEntryKey())
        .contains("issuer=Test%20Issuer");
    verify(userRepository).save(user);
  }

  @Test
  void startEnrollment_doesNotStoreThePlaintextSecret() {
    User user = new User("alice@example.com", "hash");

    MfaEnrollmentResponse response = service.startEnrollment(user);

    assertThat(user.getTotpSecret()).doesNotContain(response.manualEntryKey());
  }

  @Test
  void startEnrollment_regeneratesSecretWhileStillPending() {
    User user = new User("alice@example.com", "hash");

    service.startEnrollment(user);
    String first = user.getTotpSecret();
    service.startEnrollment(user);

    assertThat(user.getTotpSecret()).isNotEqualTo(first);
  }

  @Test
  void startEnrollment_throwsWhenAlreadyEnabled() {
    User user = new User("alice@example.com", "hash");
    user.setMfaEnabled(true);

    assertThatThrownBy(() -> service.startEnrollment(user))
        .isInstanceOf(MfaAlreadyEnabledException.class);
    verify(userRepository, never()).save(user);
  }

  // --- confirmEnrollment
  // -----------------------------------------------------------------------

  @Test
  void confirmEnrollment_activatesMfa_andConsumesTheInterval() {
    User user = userWithPendingSecret();
    when(userRepository.advanceMfaInterval(1L, NOW_INTERVAL)).thenReturn(1);

    service.confirmEnrollment(user, CODE_NOW);

    assertThat(user.isMfaEnabled()).isTrue();
    verify(userRepository).advanceMfaInterval(1L, NOW_INTERVAL);
    verify(userRepository).save(user);
  }

  @Test
  void confirmEnrollment_returnsTenUniqueBackupCodes_andReplacesAnyPriorOnes() {
    User user = userWithPendingSecret();
    when(userRepository.advanceMfaInterval(1L, NOW_INTERVAL)).thenReturn(1);

    BackupCodesResponse response = service.confirmEnrollment(user, CODE_NOW);

    assertThat(response.backupCodes()).hasSize(10);
    assertThat(response.backupCodes()).doesNotHaveDuplicates();
    verify(backupCodeRepository).deleteByUserId(1L);
    verify(backupCodeRepository).saveAll(argThat((List<BackupCode> saved) -> saved.size() == 10));
  }

  @Test
  void confirmEnrollment_rejectsWrongCode_withoutConsumingOrActivating() {
    User user = userWithPendingSecret();

    assertThatThrownBy(() -> service.confirmEnrollment(user, "000000"))
        .isInstanceOf(InvalidMfaCodeException.class);

    assertThat(user.isMfaEnabled()).isFalse();
    verify(userRepository, never()).advanceMfaInterval(anyLong(), anyLong());
    verify(userRepository, never()).save(user);
  }

  @Test
  void confirmEnrollment_rejectsMalformedCode() {
    User user = userWithPendingSecret();

    for (String bad : new String[] {null, "", "abc", "5924"}) {
      assertThatThrownBy(() -> service.confirmEnrollment(user, bad))
          .as("code=%s", bad)
          .isInstanceOf(InvalidMfaCodeException.class);
    }
    assertThat(user.isMfaEnabled()).isFalse();
  }

  @Test
  void confirmEnrollment_rejectsCodeWhenAnotherRequestAlreadyConsumedTheInterval() {
    // Two concurrent requests with the same code: both pass verify(), the DB
    // compare-and-set
    // lets only one through. The loser sees 0 updated rows and must be rejected.
    User user = userWithPendingSecret();
    when(userRepository.advanceMfaInterval(1L, NOW_INTERVAL)).thenReturn(0);

    assertThatThrownBy(() -> service.confirmEnrollment(user, CODE_NOW))
        .isInstanceOf(InvalidMfaCodeException.class);

    assertThat(user.isMfaEnabled()).isFalse();
    verify(userRepository, never()).save(user);
  }

  @Test
  void confirmEnrollment_rejectsCodeFromAnIntervalAtOrBeforeTheLastUsedOne() {
    User user = userWithPendingSecret();
    user.setMfaLastUsedInterval(NOW_INTERVAL);

    assertThatThrownBy(() -> service.confirmEnrollment(user, CODE_NOW))
        .isInstanceOf(InvalidMfaCodeException.class);

    verify(userRepository, never()).advanceMfaInterval(anyLong(), anyLong());
  }

  @Test
  void confirmEnrollment_throwsNotStarted_whenNoPendingSecret() {
    User user = new User("alice@example.com", "hash");
    user.setId(1L);

    assertThatThrownBy(() -> service.confirmEnrollment(user, CODE_NOW))
        .isInstanceOf(MfaNotStartedException.class);
  }

  @Test
  void confirmEnrollment_throwsNotStarted_whenStoredSecretIsUnreadable() {
    User user = new User("alice@example.com", "hash");
    user.setId(1L);
    user.setTotpSecret("this-is-not-a-valid-ciphertext");

    assertThatThrownBy(() -> service.confirmEnrollment(user, CODE_NOW))
        .isInstanceOf(MfaNotStartedException.class);

    verify(userRepository, never()).advanceMfaInterval(anyLong(), anyLong());
  }

  @Test
  void confirmEnrollment_throwsWhenAlreadyEnabled() {
    User user = userWithPendingSecret();
    user.setMfaEnabled(true);

    assertThatThrownBy(() -> service.confirmEnrollment(user, CODE_NOW))
        .isInstanceOf(MfaAlreadyEnabledException.class);
    verify(userRepository, never()).advanceMfaInterval(anyLong(), anyLong());
  }

  // --- QR code
  // ---------------------------------------------------------------------------------

  @Test
  void startEnrollment_returnsQrThatDecodesToTheSameOtpauthUri() {
    User user = new User("alice@example.com", "hash");

    MfaEnrollmentResponse response = service.startEnrollment(user);

    assertThat(response.qrCodeDataUri()).startsWith("data:image/png;base64,");
    assertThat(QrTestSupport.decodeDataUri(response.qrCodeDataUri()))
        .isEqualTo(response.otpauthUri());
  }

  @Test
  void pendingEnrollmentQr_decodesToTheUriForTheStoredSecret() {
    User user = userWithPendingSecret();

    byte[] png = service.pendingEnrollmentQr(user);

    assertThat(QrTestSupport.decode(png))
        .isEqualTo(
            "otpauth://totp/Test%20Issuer:alice@example.com"
                + "?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test%20Issuer");
  }

  @Test
  void pendingEnrollmentQr_matchesTheQrReturnedByStartEnrollment() {
    User user = new User("alice@example.com", "hash");

    MfaEnrollmentResponse started = service.startEnrollment(user);

    assertThat(QrTestSupport.decode(service.pendingEnrollmentQr(user)))
        .isEqualTo(started.otpauthUri());
  }

  @Test
  void pendingEnrollmentQr_throwsNotStarted_whenNoPendingSecret() {
    User user = new User("alice@example.com", "hash");

    assertThatThrownBy(() -> service.pendingEnrollmentQr(user))
        .isInstanceOf(MfaNotStartedException.class);
  }

  @Test
  void pendingEnrollmentQr_throwsNotStarted_whenStoredSecretIsUnreadable() {
    User user = new User("alice@example.com", "hash");
    user.setTotpSecret("this-is-not-a-valid-ciphertext");

    assertThatThrownBy(() -> service.pendingEnrollmentQr(user))
        .isInstanceOf(MfaNotStartedException.class);
  }

  @Test
  void pendingEnrollmentQr_throwsWhenAlreadyEnabled_soTheSecretIsNeverShownAgain() {
    User user = userWithPendingSecret();
    user.setMfaEnabled(true);

    assertThatThrownBy(() -> service.pendingEnrollmentQr(user))
        .isInstanceOf(MfaAlreadyEnabledException.class);
  }

  // --- verifyLoginCode (TOTP + backup code fallback)
  // -------------------------------------------

  private User enabledUser() {
    User user = userWithPendingSecret();
    user.setMfaEnabled(true);
    return user;
  }

  @Test
  void verifyLoginCode_acceptsTotpCode_andConsumesTheInterval() {
    User user = enabledUser();
    when(userRepository.advanceMfaInterval(1L, NOW_INTERVAL)).thenReturn(1);

    assertThat(service.verifyLoginCode(user, CODE_NOW)).isTrue();
    verify(userRepository).advanceMfaInterval(1L, NOW_INTERVAL);
    verify(backupCodeRepository, never()).findByUserIdAndUsedFalse(anyLong());
  }

  @Test
  void verifyLoginCode_fallsBackToBackupCode_whenTotpDoesNotMatch() {
    User user = enabledUser();
    BackupCode stored = backupCodeEntity(7L, "ABCD-EFGH");
    when(backupCodeRepository.findByUserIdAndUsedFalse(1L)).thenReturn(List.of(stored));
    when(backupCodeRepository.markUsed(7L)).thenReturn(1);

    assertThat(service.verifyLoginCode(user, "ABCD-EFGH")).isTrue();
    verify(backupCodeRepository).markUsed(7L);
  }

  @Test
  void verifyLoginCode_backupCodeIsSingleUse_soASecondAttemptFails() {
    User user = enabledUser();
    BackupCode stored = backupCodeEntity(7L, "ABCD-EFGH");
    when(backupCodeRepository.findByUserIdAndUsedFalse(1L)).thenReturn(List.of(stored));
    when(backupCodeRepository.markUsed(7L)).thenReturn(0); // already consumed

    assertThat(service.verifyLoginCode(user, "ABCD-EFGH")).isFalse();
  }

  @Test
  void verifyLoginCode_rejectsUnknownBackupCode() {
    User user = enabledUser();
    when(backupCodeRepository.findByUserIdAndUsedFalse(1L))
        .thenReturn(List.of(backupCodeEntity(7L, "ABCD-EFGH")));

    assertThat(service.verifyLoginCode(user, "ZZZZ-ZZZZ")).isFalse();
    verify(backupCodeRepository, never()).markUsed(anyLong());
  }

  @Test
  void verifyLoginCode_returnsFalse_whenMfaNotEnabled() {
    User user = userWithPendingSecret();

    assertThat(service.verifyLoginCode(user, CODE_NOW)).isFalse();
    verify(backupCodeRepository, never()).findByUserIdAndUsedFalse(anyLong());
  }

  // --- disable
  // ----------------------------------------------------------------------------------

  private User enabledUserWithPassword(String rawPassword) {
    User user = enabledUser();
    user.setPasswordHash(passwordEncoder.encode(rawPassword));
    return user;
  }

  @Test
  void disable_turnsOffMfa_clearsSecretAndBackupCodes_whenPasswordCorrect() {
    User user = enabledUserWithPassword("CorrectHorse1!");

    service.disable(user, "CorrectHorse1!");

    assertThat(user.isMfaEnabled()).isFalse();
    assertThat(user.getTotpSecret()).isNull();
    verify(userRepository).save(user);
    verify(backupCodeRepository).deleteByUserId(1L);
  }

  @Test
  void disable_rejectsWrongPassword_withoutTurningMfaOff() {
    User user = enabledUserWithPassword("CorrectHorse1!");

    assertThatThrownBy(() -> service.disable(user, "WrongPassword1!"))
        .isInstanceOf(InvalidCredentialsException.class);

    assertThat(user.isMfaEnabled()).isTrue();
    verify(userRepository, never()).save(user);
    verify(backupCodeRepository, never()).deleteByUserId(anyLong());
  }

  @Test
  void disable_throwsNotStarted_whenMfaNotEnabled() {
    User user = new User("alice@example.com", "hash");

    assertThatThrownBy(() -> service.disable(user, "anything"))
        .isInstanceOf(MfaNotStartedException.class);
    verify(userRepository, never()).save(user);
  }
}
